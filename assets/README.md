# The artwork, at its source

Two files, and everything else is generated from them.

**`app.png`** (1254×1254) is the icon as drawn. `npm run icons` feeds it to
`tauri icon`, which emits every size the three platforms want into
`src-tauri/icons/` — those are committed, because `tauri::generate_context!()`
opens them at compile time, but they are outputs: change the drawing here and
regenerate, never edit a derived size by hand. It is also the image both
READMEs open with, so it stays in the repository at full resolution.

**`eFeFlow.svg`** is the vector master the PNG was exported from. Nothing in
the build reads it; it is here so the next export starts from geometry rather
than from pixels. (`public/icon.svg` is a different drawing — the mark the
application shows inside its own window — and lives with the frontend it
belongs to.)
