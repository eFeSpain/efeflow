/* The ruleset the product offers, and the reason it lives here rather than in
   app.js: a sample that does not survive its own round-trip is worse than no
   sample at all, and here the tests can hold it to that.
 *
 * It is never loaded on its own. The application opens on the blank skeleton
 * in model.js — the user asks for this from the import dialog and sees the
 * round-trip review before anything replaces their work. */

/* A generic ruleset, offered so the import path can be tried without a host.
   Addresses are RFC 1918 and RFC 5737 documentation space: a sample that ships
   in the repository must not describe anybody's real network. */
export const SAMPLE_NFT = `table inet filter {
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
}`;
