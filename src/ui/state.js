/* The three things more than one screen both reads and writes.
 *
 * Everything else that looked like shared state turned out not to be: of the
 * twenty-seven module-level variables app.js declared on one line, seventeen
 * were touched by exactly one section and moved out with it. These three are
 * the ones that genuinely cross a boundary, and they are here rather than
 * exported from whichever file happened to declare them because an `export
 * let` is read-only to everybody but its own module — the canvas cannot set
 * the selection if the selection lives in the properties panel.
 *
 * One object, so a property can be assigned from anywhere that can see it.
 * Not a place to put things: three entries, each with a reason.
 */
export const UI = {
  /** Which rule the properties panel is showing: `{chainId, i}` or null.
   *  The canvas lights it up, the panel draws it, and a repaint after an undo
   *  has to put it back where it was. */
  sel: null,

  /** The canvas tool in hand — "pan" changes what a drag on empty space does,
   *  so the canvas asks and the toolbar decides. */
  tool: null,

  /** The canvas scale. The canvas owns the arithmetic; the side panels and
   *  the drag handlers need it to turn a screen position into a model one. */
  zoom: 1,
};
