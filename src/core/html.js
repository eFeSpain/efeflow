/* Text on its way into markup, for the core.
 *
 * A finding's `detail` is deliberately HTML — it sets rule fragments in
 * <code> — so it cannot be escaped wholesale where it is rendered. The values
 * interpolated into it come out of somebody else's ruleset, so they are
 * escaped here, where they go in. The interface has its own copy of this for
 * the same reason it has its own DOM: the core does not know about either. */
export const escape = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
