# Store assets

Draft marketing images for the Chrome Web Store / Firefox AMO listings. Regenerate the promo tile from
`tools/promo.html` and screenshots from the `demo/` + `test/` fixtures.

| File | Size | Use |
|---|---|---|
| `01-clickfix-warning.png` | 1280×800 | The red "Stop — this looks like a scam" warning over a lure page |
| `02-lure-page-banner.png` | 1280×800 | The lure-page detection banner |
| `03-agent-verdict-block.png` | 1280×800 | Paired with the agent: verdict + "Block on my device" |
| `04-popup.png` | 640×400 | The toolbar popup |
| `05-overview.png` | 1280×800 | The welcome/overview page ("what it does") |
| `promo-tile-440x280.png` | 440×280 | Chrome Web Store small promo tile |

Chrome accepts screenshots at **1280×800** or **640×400**; Firefox AMO takes screenshots at any size.
The warning/overview shots are captured full-bleed and scaled to spec (01/05 are a clean 1.6-aspect
upscale; 02/03 are padded on a dark canvas to fit the full content). Good to upload as-is; swap in
higher-resolution native captures later if you want them razor-sharp.
