# The artwork, at its source

Everything else is generated from these.

**`app.png`** (1254×1254) is the marketing tile — the mark, wordmark and
tagline on a dark rounded square. It is the image both READMEs open with, so it
stays in the repository at full resolution. It is *not* the binary icon.

**`app-icon.png`** (1092×1092) is what the application icon is built from: the
same mark and wordmark, no tile, on transparency, cropped square to its own
content. `npm run icons` feeds it to `tauri icon`, which emits every size the
three platforms want into `src-tauri/icons/`. Those are committed, because
`tauri::generate_context!()` opens them at compile time, but they are outputs —
change the drawing here and regenerate, never edit a derived size by hand. The
binary wears no dark tile, so on a desktop it floats on whatever is behind it;
that is why its source is transparent and the marketing tile is not.

**`eFeFlow.svg`** is the vector master the PNG was exported from. Nothing in
the build reads it; it is here so the next export starts from geometry rather
than from pixels. (`public/icon.svg` is a different drawing — the mark the
application shows inside its own window — and lives with the frontend it
belongs to.)
