/* The rulesets the product offers, and the reason they live here rather than in
   app.js: a sample that does not survive its own round-trip is worse than no
   sample at all, and here the tests can hold every one of them to that.
 *
 * None is ever loaded on its own. The application opens on the blank skeleton
 * in model.js — the user picks one from the import dialog and sees the
 * round-trip review before anything replaces their work.
 *
 * Every address is RFC 1918 or RFC 5737 documentation space. A ruleset that
 * ships in a public repository must not describe anybody's real network, and a
 * shipped ruleset is exactly the kind of file where somebody's internal subnets
 * get committed by accident. test/samples.test.js enforces it.
 *
 * Interface names are the conventional ones for each role rather than the
 * kernel's — wan0, lan0, wg0 — because a sample is read before it is run. */

export const SAMPLES = [
  {
    id: "generic",
    title: { en: "Filtering host", es: "Host con filtrado" },
    blurb: {
      en: "A single machine that filters its own traffic: conntrack first, a trusted set for SSH, and a default deny.",
      es: "Una máquina que filtra su propio tráfico: conntrack primero, un set de confianza para SSH, y denegación por defecto.",
    },
    nft: `table inet filter {
	set trusted_v4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.0.0/16 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 8812099 bytes 9400000000 accept
		iif "lo" counter packets 120144 bytes 16700000 accept
		ct state invalid counter packets 288 bytes 17280 drop
		ip protocol icmp limit rate 10/second counter packets 4209 bytes 293556 accept
		tcp dport 22 ip saddr @trusted_v4 counter packets 8402 bytes 1120400 accept comment "SSH from trusted only"
		tcp dport { 80, 443 } counter packets 904771 bytes 620000000 accept
		counter packets 6113 bytes 366780 drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter packets 18204113 bytes 22000000000 accept
		iifname "eth1" oifname "eth0" counter packets 9209881 bytes 12000000000 accept
		log prefix "fwd-deny " counter packets 512 bytes 30720
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}

table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" ip saddr 192.168.0.0/16 counter packets 9209881 bytes 12000000000 masquerade
	}
}`,
  },

  {
    id: "gateway",
    title: { en: "NAT gateway", es: "Pasarela NAT" },
    blurb: {
      en: "The everyday edge router: one LAN behind one uplink, masqueraded out, with nothing reaching in that the LAN did not ask for.",
      es: "El router de borde de cada día: una LAN detrás de un enlace, enmascarada hacia fuera, sin que entre nada que la LAN no haya pedido.",
    },
    nft: `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		iif "lo" counter accept
		iifname "lan0" ip protocol icmp counter accept
		iifname "lan0" udp dport { 53, 67 } counter accept comment "we are the LAN resolver and DHCP server"
		iifname "lan0" tcp dport 22 counter accept comment "management from inside only"
		counter drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		iifname "lan0" oifname "wan0" counter accept comment "the LAN goes out"
		oifname "lan0" tcp flags syn tcp option maxseg size set rt mtu counter comment "clamp MSS for PPPoE links"
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}

table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" ip saddr 192.168.10.0/24 counter masquerade
	}
}`,
  },

  {
    id: "dnat",
    title: { en: "Port forwarding, with hairpin", es: "Redirección de puertos, con hairpin" },
    blurb: {
      en: "DNAT from the uplink to two internal servers. The third rule is the one people forget: a LAN client asking for the public address needs the reply to come back through the gateway, or the connection dies half-open.",
      es: "DNAT desde el enlace hacia dos servidores internos. La tercera regla es la que se olvida: un cliente de la LAN que pide la dirección pública necesita que la respuesta vuelva por la pasarela, o la conexión muere a medio abrir.",
    },
    nft: `table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wan0" tcp dport 443 counter dnat to 192.168.10.20:443 comment "HTTPS to the web server"
		iifname "wan0" tcp dport 2222 counter dnat to 192.168.10.30:22 comment "SSH moved off the usual port"
		iifname "lan0" ip daddr 203.0.113.10 tcp dport 443 counter dnat to 192.168.10.20:443 comment "hairpin: the LAN asking for the public address"
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 192.168.10.0/24 ip daddr 192.168.10.20 tcp dport 443 counter snat to 192.168.10.1 comment "hairpin needs the reply to come back through us"
		oifname "wan0" counter masquerade
	}
}

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		iif "lo" counter accept
		iifname "lan0" tcp dport 22 counter accept
		counter drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		ct status dnat counter accept comment "whatever prerouting translated is allowed through"
		iifname "lan0" oifname "wan0" counter accept
	}
}`,
  },

  {
    id: "wireguard",
    title: { en: "WireGuard VPN server", es: "Servidor VPN WireGuard" },
    blurb: {
      en: "A tunnel endpoint: one port open to the world, peers reaching the LAN, and peers explicitly not reaching each other. Management is only offered inside the tunnel.",
      es: "Un extremo de túnel: un puerto abierto al mundo, los peers alcanzan la LAN, y los peers explícitamente no se alcanzan entre sí. La gestión solo se ofrece dentro del túnel.",
    },
    nft: `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		iif "lo" counter accept
		udp dport 51820 counter accept comment "WireGuard listens here, and nothing else is public"
		iifname "wg0" ip protocol icmp counter accept
		iifname "wg0" tcp dport 22 counter accept comment "management over the tunnel only"
		counter drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter accept
		iifname "wg0" oifname "wg0" counter drop comment "peers do not reach each other"
		iifname "wg0" ip saddr 10.66.0.0/24 oifname "lan0" counter accept comment "peers reach the LAN"
		iifname "lan0" oifname "wg0" counter accept
		iifname "wg0" oifname "wan0" counter accept comment "peers browsing through the tunnel"
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}

table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.66.0.0/24 oifname "wan0" counter masquerade
	}
}`,
  },

  {
    id: "balancer",
    title: { en: "Load balancer", es: "Balanceador de carga" },
    blurb: {
      en: "Two ways to spread connections across backends. numgen takes them in turn; jhash sends the same client to the same backend, which is what anything holding a session needs.",
      es: "Dos formas de repartir conexiones entre servidores. numgen las reparte por turnos; jhash manda el mismo cliente al mismo servidor, que es lo que necesita cualquier cosa con sesión.",
    },
    nft: `table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wan0" tcp dport 80 counter dnat to numgen inc mod 3 map { 0 : 10.20.0.11, 1 : 10.20.0.12, 2 : 10.20.0.13 } comment "plain round robin"
		iifname "wan0" tcp dport 443 counter dnat to jhash ip saddr mod 2 map { 0 : 10.20.0.11, 1 : 10.20.0.12 } comment "same client, same backend, so sessions survive"
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip daddr 10.20.0.0/24 counter snat to 10.20.0.1 comment "backends answer to us, not straight to the client"
	}
}

table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		ct status dnat counter accept comment "the balanced connections"
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		iif "lo" counter accept
		iifname "mgmt0" tcp dport 22 counter accept
		counter drop
	}
}`,
  },

  {
    id: "rogue-dhcp",
    title: { en: "Rogue DHCP filtering", es: "Filtrado de DHCP no autorizado" },
    blurb: {
      en: "A bridge filtering DHCP at layer 2. This is not DHCP snooping — snooping is a switch feature that watches the exchange and builds a binding table. What a bridge can do is refuse to carry server traffic from a port that has no business answering.",
      es: "Un bridge filtrando DHCP en capa 2. Esto no es DHCP snooping — el snooping es una función del switch que observa el diálogo y construye una tabla de vínculos. Lo que un bridge sí puede hacer es negarse a transportar tráfico de servidor desde un puerto que no tiene por qué responder.",
    },
    nft: `table bridge filter {
	chain forward {
		type filter hook forward priority -200; policy accept;
		iifname "uplink0" udp sport 67 udp dport 68 counter accept comment "the one port allowed to answer DHCP"
		udp sport 67 udp dport 68 counter drop comment "any other port offering leases is rogue"
		udp sport 547 udp dport 546 counter drop comment "the same thing over DHCPv6"
		iifname "access0" arp operation reply arp saddr ip 192.168.20.1 counter drop comment "nor may it claim to be the gateway"
	}

	chain input {
		type filter hook input priority -200; policy accept;
		udp sport 67 udp dport 68 iifname != "uplink0" counter drop comment "and the bridge itself takes no lease from them"
	}
}

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		iif "lo" counter accept
		iifname "mgmt0" tcp dport 22 counter accept
		counter drop
	}
}`,
  },

  {
    id: "public-server",
    title: { en: "Hardened public server", es: "Servidor público endurecido" },
    blurb: {
      en: "A host with its ports on the open internet. Rate limits do the work that a default-deny cannot: SSH attempts are slowed to a crawl, ICMP and new connections are capped, and what is refused is logged at a rate that cannot fill a disk.",
      es: "Un host con sus puertos en internet. Los límites de tasa hacen el trabajo que la denegación por defecto no puede: los intentos de SSH se frenan, ICMP y las conexiones nuevas se acotan, y lo rechazado se registra a un ritmo que no puede llenar un disco.",
    },
    nft: `table inet filter {
	set admin_v4 {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.0/24, 203.0.113.7 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop comment "half-open and out-of-window packets go early"
		iif "lo" counter accept
		ip protocol icmp icmp type echo-request limit rate 5/second burst 10 packets counter accept
		ip protocol icmp counter drop
		tcp dport 22 ip saddr @admin_v4 counter accept comment "admins are not rate limited"
		tcp dport 22 ct state new limit rate 3/minute burst 3 packets counter accept comment "everyone else gets three tries a minute"
		tcp dport 22 ct state new counter drop comment "and the rest are guessing"
		tcp dport { 80, 443 } ct state new limit rate 200/second burst 400 packets counter accept
		tcp dport { 80, 443 } counter accept
		limit rate 5/minute burst 10 packets log prefix "in-drop " counter
		counter drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain output {
		type filter hook output priority filter; policy accept;
		ct state invalid counter drop
	}
}`,
  },
  {
    id: "campus",
    title: { en: "Campus edge router", es: "Router de borde corporativo" },
    blurb: {
      en: "The big one: three zones dispatched through a verdict map, a ban list that fills itself from the traffic, named counters and a quota, and a port-forward map on the way in.",
      es: "El grande: tres zonas repartidas con un mapa de veredictos, una lista de baneo que se llena sola con el tráfico, contadores con nombre y una cuota, y un mapa de reenvío de puertos a la entrada.",
    },
    nft: `table inet filter {
	ct helper ftp-standard {
		type "ftp" protocol tcp
	}

	counter policy_drops {
	}

	quota guest_cap {
		over 50000 mbytes
	}

	set admins {
		type ipv4_addr
		flags interval
		elements = { 10.10.0.0/24, 192.168.99.10 }
	}

	set banned {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		timeout 1h
	}

	set open_tcp {
		type inet_service
		flags interval
		elements = { 22, 80, 443, 8080-8090 }
	}

	chain early {
		type filter hook prerouting priority raw; policy accept;
		ip frag-off & 0x1fff != 0 counter drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop
		tcp flags & (fin|syn) == fin|syn counter drop
		ip saddr @banned counter drop
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter accept
		iif "lo" counter accept
		ct state invalid counter name "policy_drops" drop
		meta l4proto icmp limit rate 20/second burst 40 packets counter accept
		iifname "lan0" tcp dport 22 ip saddr @admins counter accept
		iifname "wan0" tcp dport 443 counter accept
		iifname "wan0" tcp flags syn tcp dport 22 counter add @banned { ip saddr timeout 1h } drop
		counter name "policy_drops" log prefix "in-drop " drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related counter accept
		ct state invalid counter drop
		iifname vmap { "lan0" : jump zone_lan, "dmz0" : jump zone_dmz, "gst0" : jump zone_guest }
		counter name "policy_drops" drop
	}

	chain zone_lan {
		oifname "wan0" counter accept
		oifname "dmz0" tcp dport @open_tcp counter accept
		counter log prefix "lan-deny " drop
	}

	chain zone_dmz {
		oifname "wan0" ct state new tcp dport { 80, 443 } counter accept
		counter log prefix "dmz-deny " drop
	}

	chain zone_guest {
		oifname "wan0" quota name "guest_cap" counter drop
		oifname "wan0" counter accept
		counter drop
	}

	chain output {
		type filter hook output priority filter; policy accept;
		ct state new tcp dport 21 ct helper set "ftp-standard" counter accept
	}
}

table ip nat {
	map port_fwd {
		type inet_service : ipv4_addr
		elements = { 8443 : 10.20.0.11, 2222 : 10.20.0.12 }
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wan0" tcp dport { 8443, 2222 } dnat to tcp dport map @port_fwd
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" ip saddr 10.10.0.0/16 counter masquerade
	}
}`,
  },
  {
    id: "hosting",
    title: { en: "Public dual-stack server", es: "Servidor público de doble pila" },
    blurb: {
      en: "A machine that forwards nothing and publishes two ports: v4 and v6 side by side, per-source rate limiting that greylists whatever floods it, a counter per service and a monthly egress quota.",
      es: "Una máquina que no reenvía nada y publica dos puertos: v4 y v6 en paralelo, límite por origen que mete en lista gris a quien la inunda, un contador por servicio y una cuota mensual de salida.",
    },
    nft: `table inet web {
	counter http_hits {
	}

	counter https_hits {
	}

	counter probes_blocked {
	}

	quota egress_month {
		over 2000000 mbytes
	}

	set knocking {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		timeout 30s
	}

	set greylist {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		timeout 12h
	}

	set office_v4 {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.0/24 }
	}

	set office_v6 {
		type ipv6_addr
		flags interval
		elements = { 2001:db8:c0fe::/48 }
	}

	set published {
		type inet_service
		elements = { 80, 443 }
	}

	chain notrack_syn {
		type filter hook prerouting priority raw; policy accept;
		tcp dport @published tcp flags syn notrack
	}

	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" counter accept
		ct state established,related counter accept
		ct state invalid counter name "probes_blocked" drop
		ip saddr @greylist counter name "probes_blocked" drop
		meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second counter accept
		meta l4proto ipv6-icmp icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big } limit rate 5/second counter accept
		ip saddr @office_v4 tcp dport 22 counter accept comment "management from the office only"
		ip6 saddr @office_v6 tcp dport 22 counter accept comment "same, over v6"
		tcp dport 22 counter add @greylist { ip saddr timeout 12h } drop
		tcp dport 80 counter name "http_hits" jump rate_guard
		tcp dport 443 counter name "https_hits" jump rate_guard
		ct state untracked tcp dport @published counter accept
		counter name "probes_blocked" log prefix "srv-drop " level info drop
	}

	chain rate_guard {
		ip saddr @office_v4 counter accept
		meter flood { ip saddr limit rate over 200/second burst 300 packets } counter add @knocking { ip saddr } drop
		ip saddr @knocking counter drop
		counter accept
	}

	chain output {
		type filter hook output priority filter; policy accept;
		oifname "eth0" quota name "egress_month" counter log prefix "quota-exceeded " drop
		ct state new udp dport 53 counter accept
		counter accept
	}
}`,
  },
];

/* The one the import dialog starts on. */
export const SAMPLE_NFT = SAMPLES[0].nft;

export const sampleById = (id) => SAMPLES.find((s) => s.id === id) || null;
