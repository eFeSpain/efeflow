/* The vocabularies you drag onto rules: services, protocols, conntrack helpers.
 *
 * This is knowledge about the world, not about anybody's firewall — telnet is
 * 23 everywhere. That is why the ones you add by hand are kept on the machine
 * rather than in the project file: a port you had to look up once should be
 * there in the next project too, without having saved anything.
 *
 * Contrast with the interfaces and networks in project.scratch, which describe
 * the box you are writing rules for and travel with the project.
 *
 * `p` is what goes after `dport`, so a range or a set literal is as valid as a
 * number — nft takes `dport 6000-6063` and `dport { 80, 443 }` alike. */

export const SERVICES = [
  { n: "ftp",         p: "21",        proto: "tcp" },
  { n: "ftp-data",    p: "20",        proto: "tcp" },
  { n: "ssh",         p: "22",        proto: "tcp" },
  { n: "telnet",      p: "23",        proto: "tcp" },
  { n: "smtp",        p: "25",        proto: "tcp" },
  { n: "submission",  p: "587",       proto: "tcp" },
  { n: "smtps",       p: "465",       proto: "tcp" },
  { n: "dns",         p: "53",        proto: "udp" },
  { n: "dns-tcp",     p: "53",        proto: "tcp" },
  { n: "dot",         p: "853",       proto: "tcp" },
  { n: "dhcp",        p: "67",        proto: "udp" },
  { n: "dhcpv6",      p: "547",       proto: "udp" },
  { n: "tftp",        p: "69",        proto: "udp" },
  { n: "http",        p: "80",        proto: "tcp" },
  { n: "https",       p: "443",       proto: "tcp" },
  { n: "http-alt",    p: "8080",      proto: "tcp" },
  { n: "pop3",        p: "110",       proto: "tcp" },
  { n: "pop3s",       p: "995",       proto: "tcp" },
  { n: "imap",        p: "143",       proto: "tcp" },
  { n: "imaps",       p: "993",       proto: "tcp" },
  { n: "ntp",         p: "123",       proto: "udp" },
  { n: "netbios",     p: "137-139",   proto: "udp" },
  { n: "smb",         p: "445",       proto: "tcp" },
  { n: "snmp",        p: "161",       proto: "udp" },
  { n: "snmp-trap",   p: "162",       proto: "udp" },
  { n: "ldap",        p: "389",       proto: "tcp" },
  { n: "ldaps",       p: "636",       proto: "tcp" },
  { n: "kerberos",    p: "88",        proto: "tcp" },
  { n: "syslog",      p: "514",       proto: "udp" },
  { n: "radius",      p: "1812",      proto: "udp" },
  { n: "rdp",         p: "3389",      proto: "tcp" },
  { n: "vnc",         p: "5900",      proto: "tcp" },
  { n: "mysql",       p: "3306",      proto: "tcp" },
  { n: "postgres",    p: "5432",      proto: "tcp" },
  { n: "redis",       p: "6379",      proto: "tcp" },
  { n: "mongodb",     p: "27017",     proto: "tcp" },
  { n: "mssql",       p: "1433",      proto: "tcp" },
  { n: "sip",         p: "5060",      proto: "udp" },
  { n: "sips",        p: "5061",      proto: "tcp" },
  { n: "rtp",         p: "10000-20000", proto: "udp" },
  { n: "mqtt",        p: "1883",      proto: "tcp" },
  { n: "wireguard",   p: "51820",     proto: "udp" },
  { n: "openvpn",     p: "1194",      proto: "udp" },
  { n: "ipsec-ike",   p: "500",       proto: "udp" },
  { n: "ipsec-nat-t", p: "4500",      proto: "udp" },
  { n: "l2tp",        p: "1701",      proto: "udp" },
  { n: "pptp",        p: "1723",      proto: "tcp" },
  { n: "git",         p: "9418",      proto: "tcp" },
  { n: "docker",      p: "2376",      proto: "tcp" },
  { n: "winbox",      p: "8291",      proto: "tcp" },
  { n: "proxmox",     p: "8006",      proto: "tcp" },
  { n: "minecraft",   p: "25565",     proto: "tcp" },
];

/* What people type into the add box: `telnet 23`, `tftp 69/udp`, or
   `rtp 10000-20000/udp`. One line rather than three fields, because it reads
   the way the thing is written down everywhere else. tcp when unstated —
   it is the answer more often than not, and it is visible afterwards. */
export function parseService(text) {
  const m = String(text || "").trim().match(/^([\w.-]+)[\s:=]+(\S+?)(?:\/(tcp|udp))?$/i);
  if (!m) return null;
  const [, n, p, proto] = m;
  if (!validPort(p)) return null;
  return { n: n.toLowerCase(), p, proto: (proto || "tcp").toLowerCase() };
}

/* A port, a range, or a braced set — all of which nft accepts after dport. */
export function validPort(p) {
  const one = (v) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
  const s = String(p).trim();
  if (/^\{.*\}$/.test(s))
    return s.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean).every(one);
  if (s.includes("-")) {
    const [a, b] = s.split("-");
    return one(a) && one(b) && +a <= +b;
  }
  return one(s);
}

/* Built-ins first, then yours; a name you define wins, so a catalogue entry
   you disagree with can be replaced rather than worked around. */
export function catalogue(custom = [], base = SERVICES) {
  const m = new Map(base.map((s) => [s.n, { ...s, own: false }]));
  for (const s of custom) m.set(s.n, { ...s, own: true });
  return [...m.values()].sort((a, b) => a.n.localeCompare(b.n));
}

export const protoOf = (name, custom = []) =>
  catalogue(custom).find((s) => s.n === name)?.proto || "tcp";

/* ── protocols ──────────────────────────────────────────────────────────
   What goes after `meta l4proto`. nft also takes a bare number, which is why
   a custom entry is allowed: the list below is the useful subset, not the
   whole of /etc/protocols. */
export const PROTOCOLS = [
  { n: "tcp" },      { n: "udp" },     { n: "icmp" },   { n: "icmpv6" },
  { n: "sctp" },     { n: "dccp" },    { n: "udplite" },
  { n: "esp" },      { n: "ah" },      { n: "comp" },
  { n: "gre" },      { n: "igmp" },    { n: "ospf" },   { n: "vrrp" },
  { n: "l2tp" },     { n: "mh" },      { n: "ipv6-frag" },
];

/* ── conntrack helpers ──────────────────────────────────────────────────
   A helper reads the payload of a protocol that negotiates a second
   connection, so conntrack can mark it `related`. FTP is the reason they
   exist: the data channel is on a port nobody could have written a rule for.

   Modern kernels want the helper assigned explicitly in a rule rather than
   loaded globally, which is what dragging one of these writes. */
export const HELPERS = [
  { n: "ftp",    p: "21",   proto: "tcp" },
  { n: "sip",    p: "5060", proto: "udp" },
  { n: "tftp",   p: "69",   proto: "udp" },
  { n: "h323",   p: "1720", proto: "tcp" },
  { n: "pptp",   p: "1723", proto: "tcp" },
  { n: "irc",    p: "6667", proto: "tcp" },
  { n: "snmp",   p: "161",  proto: "udp" },
  { n: "amanda", p: "10080", proto: "udp" },
  { n: "sane",   p: "6566", proto: "tcp" },
];

/* Which vocabularies you can add to, and how a line you type is read.
   Everything else in the palette is closed by nftables' own grammar: there is
   no eighth verdict, and inventing one would emit a ruleset that does not
   load. Those lists are completed, not opened. */
export const OWNABLE = {
  SV: {
    key: "services",
    hint: { en: "name port, or name port/udp", es: "nombre puerto, o nombre puerto/udp" },
    example: "telnet 23",
    parse: parseService,
  },
  PR: {
    key: "protocols",
    hint: { en: "a protocol name or number", es: "un nombre o número de protocolo" },
    example: "gre",
    parse: (text) => {
      const n = String(text || "").trim().toLowerCase();
      return /^[a-z0-9][\w.-]*$/.test(n) ? { n } : null;
    },
  },
  HL: {
    key: "helpers",
    hint: { en: "name port, or name port/udp", es: "nombre puerto, o nombre puerto/udp" },
    example: "h323 1720",
    parse: parseService,
  },
};

export const BUILT_IN = { SV: SERVICES, PR: PROTOCOLS, HL: HELPERS };

export const emptyVocabulary = () => ({ services: [], protocols: [], helpers: [] });

/* ── templates ──────────────────────────────────────────────────────────
   Groups of rules that always arrive together. They used to be four labels
   with invented rule counts that did nothing when dropped, which is the worst
   combination: it looks finished and is not.

   Nothing here names an address or an interface that is not the user's, so a
   template cannot smuggle somebody else's network into a ruleset. Where one is
   unavoidable it is left for them to fill in. */
export const TEMPLATES = [
  {
    id: "stateful",
    title: { en: "Stateful baseline", es: "Base con estado" },
    rules: [
      { expr: "ct state established,related", verdict: "accept", ctr: true },
      { expr: "ct state invalid", verdict: "drop", ctr: true },
      { expr: "iif lo", verdict: "accept", ctr: true },
    ],
  },
  {
    id: "wan",
    title: { en: "WAN hardening", es: "Fortificación WAN" },
    rules: [
      { expr: "ct state invalid", verdict: "drop", ctr: true },
      { expr: "ip protocol icmp icmp type echo-request limit rate 5/second burst 10 packets",
        verdict: "accept", ctr: true },
      { expr: "ip protocol icmp", verdict: "drop", ctr: true },
      { expr: "tcp dport 22 ct state new limit rate 3/minute burst 3 packets",
        verdict: "accept", ctr: true },
      { expr: "limit rate 5/minute burst 10 packets log prefix \"wan-drop \"",
        verdict: "continue", implicit: true, ctr: true },
    ],
  },
  {
    id: "docker",
    title: { en: "Docker-safe forward", es: "Forward compatible con Docker" },
    rules: [
      { expr: "ct state established,related", verdict: "accept", ctr: true },
      { expr: "ct status dnat", verdict: "accept", ctr: true,
        cmt: "published container ports" },
      { expr: "ct state invalid", verdict: "drop", ctr: true },
    ],
  },
  {
    id: "vpn",
    title: { en: "VPN split tunnel", es: "VPN túnel dividido" },
    rules: [
      { expr: "ct state established,related", verdict: "accept", ctr: true },
      { expr: "iifname \"wg0\" oifname \"wg0\"", verdict: "drop", ctr: true,
        cmt: "peers do not reach each other" },
      { expr: "iifname \"wg0\"", verdict: "accept", ctr: true },
    ],
  },
];

export const templateById = (id) => TEMPLATES.find((x) => x.id === id) || null;
