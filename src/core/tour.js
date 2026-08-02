/* The interactive tutorial, as data.
 *
 * Reading about a canvas does not teach it. These steps walk someone through
 * building one real rule — SSH reachable from one network and nowhere else —
 * and then show them the same rule as source, as a finding, and as a packet.
 *
 * The steps live here rather than in app.js for the same reason the samples do:
 * they make promises a test can check. Every one is bilingual, points at
 * something the markup actually has, and belongs to a screen the rail can
 * reach.
 *
 * `done` is what makes it a tutorial rather than a slideshow. A step with one
 * waits for the user to do the thing; a step without one is something to read,
 * and offers a button. Predicates read the model and nothing else, so this file
 * stays free of the DOM like the rest of core/.
 *
 * `baseline` is captured when the step opens, so a step can say "one more rule
 * than there was" without assuming what the ruleset started as. */

const chain = (m, id) => m.chains.find((c) => c.id === id);
const rules = (m, id) => chain(m, id)?.rules ?? [];
const theRule = (m) => rules(m, "input").find((r) => /\bdport\s+22\b/.test(r.expr || ""));

export const TOUR = [
  {
    id: "welcome",
    screen: "editor",
    title: { en: "Let us build one rule", es: "Vamos a montar una regla" },
    body: {
      en: "SSH reachable from one network and nowhere else. It is four fields, and at the end you will have seen it as a card, as nft source, as a finding and as a packet — which is the whole tool.",
      es: "SSH accesible desde una red y desde ninguna otra. Son cuatro campos, y al final la habrás visto como tarjeta, como código nft, como hallazgo y como paquete — que es la herramienta entera.",
    },
  },
  {
    id: "canvas",
    screen: "editor",
    target: "#chains .chain",
    title: { en: "Position is meaning", es: "La posición es significado" },
    body: {
      en: "Each card is a chain, placed at the netfilter hook it is attached to — left to right, in the order a packet meets them — and at its priority, top to bottom. You read evaluation order off the screen instead of rebuilding it in your head.",
      es: "Cada tarjeta es una cadena, situada en el hook de netfilter al que está enganchada —de izquierda a derecha, en el orden en que un paquete los encuentra— y en su prioridad, de arriba abajo. El orden de evaluación se lee en la pantalla en lugar de reconstruirlo mentalmente.",
    },
  },
  {
    id: "add",
    screen: "editor",
    target: '.chain[data-chain$="/input"] .addrule',
    title: { en: "Add a rule to input", es: "Añade una regla a input" },
    body: {
      en: "input is the chain a packet addressed to this machine walks. Press Add rule at the foot of that card.",
      es: "input es la cadena que recorre un paquete dirigido a esta máquina. Pulsa Añadir regla al pie de esa tarjeta.",
    },
    baseline: (m) => rules(m, "input").length,
    done: (m, base) => rules(m, "input").length > base,
  },
  {
    id: "port",
    screen: "editor",
    target: "#f-dport",
    title: { en: "Say which port", es: "Di qué puerto" },
    body: {
      en: "The panel on the right edits the selected rule. Put 22 in Destination port. The rule card and the source below both change as you type — there is no save step.",
      es: "El panel de la derecha edita la regla seleccionada. Pon 22 en Puerto destino. La tarjeta y el código de abajo cambian mientras escribes — no hay paso de guardar.",
    },
    done: (m) => !!theRule(m),
  },
  {
    id: "source",
    screen: "editor",
    target: "#f-saddr",
    title: { en: "And from where", es: "Y desde dónde" },
    body: {
      en: "Put 192.168.1.0/24 in Source address. Without it the rule offers SSH to the entire internet, which is the single most common way a firewall is written wrong.",
      es: "Pon 192.168.1.0/24 en Dirección origen. Sin eso, la regla ofrece SSH a todo internet, que es la forma más común de escribir mal un firewall.",
    },
    done: (m) => /\bsaddr\b/.test(theRule(m)?.expr || ""),
  },
  {
    id: "verdict",
    screen: "editor",
    target: "#f-verdict",
    title: { en: "Decide the verdict", es: "Decide el veredicto" },
    body: {
      en: "Set it to accept. In nftables accept ends this chain, not the packet — it carries on to the next hook. Only drop and reject end it outright.",
      es: "Ponlo en accept. En nftables accept termina esta cadena, no el paquete — sigue hasta el siguiente hook. Solo drop y reject lo terminan del todo.",
    },
    done: (m) => theRule(m)?.verdict === "accept",
  },
  {
    id: "code",
    screen: "editor",
    target: "#codeout",
    title: { en: "That is the source", es: "Eso es el código" },
    body: {
      en: "It was rewritten on every keystroke. This is what an export writes and what nft -c validates — not a preview of it. Click any line and it selects the rule that produced it.",
      es: "Se ha reescrito en cada pulsación. Esto es lo que escribe una exportación y lo que valida nft -c — no una vista previa. Pulsa cualquier línea y selecciona la regla que la produjo.",
    },
  },
  {
    id: "validate",
    screen: "validate",
    target: "#findings",
    title: { en: "What is wrong with it", es: "Qué tiene de malo" },
    body: {
      en: "Findings are derived from the ruleset every time it changes — never authored, never stale. A rule an earlier one already decides is reported as shadowed, whatever it says.",
      es: "Los hallazgos se derivan del ruleset en cada cambio — nunca escritos a mano, nunca obsoletos. Una regla que ya decide otra anterior se reporta como eclipsada, diga lo que diga.",
    },
  },
  {
    id: "simulate",
    screen: "sim",
    target: ".sim-form",
    title: { en: "Send a packet through it", es: "Manda un paquete por ella" },
    body: {
      en: "Describe a packet and watch it walk the chains to a verdict. Put 22 in Destination port and 192.168.1.10 in Source address and it should reach your rule. Change the source and it should not.",
      es: "Describe un paquete y míralo recorrer las cadenas hasta un veredicto. Pon 22 en Puerto destino y 192.168.1.10 en Dirección origen y debería llegar a tu regla. Cambia el origen y no debería.",
    },
  },
  {
    id: "end",
    screen: "editor",
    title: { en: "That is the loop", es: "Ese es el ciclo" },
    body: {
      en: "Edit, read the source, check the findings, send a packet. Everything else — sets, NAT, importing what you already run — is the same four moves on a larger ruleset. The guide has the rest.",
      es: "Editar, leer el código, mirar los hallazgos, mandar un paquete. Todo lo demás — sets, NAT, importar lo que ya tienes en marcha — son los mismos cuatro movimientos sobre un ruleset mayor. El resto está en la guía.",
    },
  },
];

export const tourStep = (i) => TOUR[i] ?? null;
