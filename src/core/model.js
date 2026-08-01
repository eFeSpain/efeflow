/* The ruleset itself, plus the vocabulary every other module shares. */
export const HOOKS = ["prerouting","input","forward","output","postrouting"];

export const R = (expr,verdict,o={}) => Object.assign({expr,verdict,on:true,pkts:0,bytes:0},o);

export const MODEL = {
  chains:[
    { id:"raw_pre", table:"inet fw", hook:"prerouting", prio:-300, type:"filter", policy:"accept",
      rules:[
        R("ip saddr @blocklist","drop",{pkts:184203,bytes:11_800_000,cmt:"Threat-feed drop, 24h timeout"}),
        R("ct state invalid","drop",{pkts:9412,bytes:640_000}),
        R("meta iifname \"wan0\" ip saddr 10.0.0.0/8","drop",{pkts:38,bytes:2280,cmt:"Anti-spoof: RFC1918 from WAN"}),
      ]},
    { id:"nat_pre", table:"ip nat", hook:"prerouting", prio:-100, type:"nat", policy:"accept",
      rules:[
        R("iifname \"wan0\" tcp dport 8443","dnat",{to:"10.20.0.15:443",pkts:1204,bytes:96_320,cmt:"Ingress controller"}),
        R("ip saddr @admin_nets tcp dport 8443","dnat",{to:"10.20.0.31:443",pkts:0,bytes:0,cmt:"Staging ingress"}),
        R("iifname \"wan0\" udp dport 51820","accept",{cmt:"WireGuard, no translation"}),
      ]},
    { id:"input", table:"inet fw", hook:"input", prio:0, type:"filter", policy:"drop",
      rules:[
        R("ct state established,related","accept",{pkts:44_812_099,bytes:38_400_000_000}),
        R("iif lo","accept",{pkts:820_144,bytes:96_700_000}),
        R("ct state invalid","drop",{pkts:2288,bytes:137_280}),
        R("meta l4proto { icmp, ipv6-icmp } limit rate 20/second","accept",{pkts:14_209,bytes:1_193_556}),
        /* four rules that differ only by dport — the optimiser finds these */
        R("tcp dport 22 ip saddr @admin_nets","accept",{pkts:18_204,bytes:4_368_960,cmt:"Management plane"}),
        R("tcp dport 443 ip saddr @admin_nets","accept",{pkts:12_880,bytes:3_091_200}),
        R("tcp dport 8291 ip saddr @admin_nets","accept",{pkts:6_104,bytes:1_464_960}),
        R("tcp dport 161 ip saddr @admin_nets","accept",{pkts:1_214,bytes:291_360}),
        R("tcp dport { 80, 443 }","accept",{pkts:2_904_771,bytes:1_820_000_000}),
        R("udp dport 51820","accept",{pkts:1_204_882,bytes:1_400_000_000,cmt:"WireGuard"}),
        R("ip saddr 10.10.0.0/24 tcp dport 443","accept",{pkts:0,bytes:0}),
        R("limit rate 5/second log prefix \"fw-input-drop \"","drop",{pkts:60_113,bytes:3_606_780}),
      ]},
    { id:"forward", table:"inet fw", hook:"forward", prio:0, type:"filter", policy:"drop",
      rules:[
        R("ct state established,related","accept",{pkts:98_204_113,bytes:112_000_000_000}),
        R("ct status dnat","accept",{pkts:1_920_004,bytes:2_400_000_000,cmt:"Allow translated flows"}),
        R("iifname \"br-lan\" oifname \"wan0\"","accept",{pkts:41_209_881,bytes:52_000_000_000}),
        R("iifname \"wg0\" ip saddr @vpn_peers","jump",{to:"fwd_mgmt",pkts:204_882,bytes:184_000_000}),
        R("iifname \"vlan30\" oifname \"br-lan\"","reject",{to:"icmpx admin-prohibited",pkts:1044,bytes:62_640,cmt:"IoT stays isolated"}),
        R("iifname \"docker0\"","accept",{pkts:8_204_991,bytes:6_100_000_000}),
        R("log prefix \"fw-fwd-drop \" limit rate 5/second","drop",{pkts:88_402,bytes:5_304_120}),
      ]},
    { id:"fwd_mgmt", table:"inet fw", hook:null, prio:null, type:"regular", policy:null,
      rules:[
        R("tcp dport @mgmt_ports","accept",{pkts:18_402,bytes:4_416_480}),
        R("","drop",{pkts:204,bytes:12_240}),
      ]},
    { id:"output", table:"inet fw", hook:"output", prio:0, type:"filter", policy:"accept",
      rules:[
        R("ct state established,related","accept",{pkts:44_902_118,bytes:9_800_000_000}),
        R("oif lo","accept",{pkts:820_144,bytes:96_700_000}),
        R("ip daddr @blocklist log prefix \"egress-block \"","drop",{pkts:12,bytes:720}),
      ]},
    { id:"nat_post", table:"ip nat", hook:"postrouting", prio:100, type:"nat", policy:"accept",
      rules:[
        R("oifname \"wan0\" ip saddr 10.10.0.0/24","snat",{to:"masquerade",pkts:41_209_881,bytes:52_000_000_000}),
        R("oifname \"wan0\" ip saddr 172.17.0.0/16","snat",{to:"masquerade",pkts:8_204_991,bytes:6_100_000_000}),
      ]},
  ],
  sets:[
    {n:"admin_nets", table:"inet fw", t:"ipv4_addr", f:"interval", el:["10.10.0.0/24","10.10.4.0/24","10.20.0.0/16","192.168.88.0/24","198.51.100.7/32","203.0.113.0/28"]},
    {n:"mgmt_ports", table:"inet fw", t:"inet_service", f:"", el:["22","443","161","8291"]},
    {n:"vpn_peers", table:"inet fw", t:"ipv4_addr", f:"", el:["10.44.0.2","10.44.0.3","10.44.0.4"]},
    {n:"blocklist", table:"inet fw", t:"ipv4_addr", f:"interval, timeout", el:["/* 1 248 elements */"]},
    {n:"cdn_edges", table:"inet fw", t:"ipv6_addr", f:"interval", el:["2606:4700::/32","2a02:26f0::/32","/* +36 more */"]},
  ],
};

let FIND = [];   /* current analyser output — the canvas and the properties
                    panel read it, so a flagged rule is flagged everywhere */
export const VCOLOR = {accept:"--v-accept",drop:"--v-drop",reject:"--v-reject",jump:"--v-jump",dnat:"--v-dnat",snat:"--v-snat",log:"--v-log"};
export const VNAME  = {accept:"ACCEPT",drop:"DROP",reject:"REJECT",jump:"JUMP",dnat:"DNAT",snat:"SNAT",log:"LOG"};
export const fmtN = n => n>=1e9?(n/1e9).toFixed(1)+"G":n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"k":String(n);
export const fmtB = n => n>=1e9?(n/1e9).toFixed(1)+" GB":n>=1e6?(n/1e6).toFixed(1)+" MB":n>=1e3?(n/1e3).toFixed(1)+" kB":n+" B";

/* verdict phrase as it appears in real nft syntax */
export function verdictText(r){
  if(r.implicit)           return "";   /* imported rule that falls through */
  if(r.verdict==="jump")   return "jump "+r.to;
  if(r.verdict==="dnat")   return "dnat to "+r.to;
  if(r.verdict==="snat")   return r.to==="masquerade" ? "masquerade" : "snat to "+r.to;
  if(r.verdict==="reject") return r.to ? "reject with "+r.to : "reject";
  return r.verdict;
}
export function ruleLine(r){ return ((r.expr ? r.expr+" " : "") + (r.pkts?"counter ":"") + verdictText(r)).trim(); }

export const UID = ch => ch.table + '/' + ch.id;
export const jumpTarget = (ch, name) =>
  MODEL.chains.find(c => c.table === ch.table && c.id === name);
export const chainOf = uid => MODEL.chains.find(c => UID(c) === uid);
