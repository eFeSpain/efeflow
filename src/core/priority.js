/* nft prints chain priorities by name; both directions are needed so an
   imported `priority filter` survives a round-trip as `priority filter`. */
export const PRIO_NAME = {
  raw: -300,
  mangle: -150,
  dstnat: -100,
  filter: 0,
  security: 50,
  srcnat: 100,
  out: 0,
};

export const NAME_PRIO = {
  "-300": "raw",
  "-150": "mangle",
  "-100": "dstnat",
  "0": "filter",
  "50": "security",
  "100": "srcnat",
};

export const prioLabel = (n) => NAME_PRIO[String(n)] || null;
