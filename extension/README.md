# Scouter Browser Defense (browser extension)

Phase 2 of Scouter's browser-threat monitoring. A Manifest V3 browser extension that catches the
**ClickFix** scam — a fake CAPTCHA / "verify you are human" / bogus-error page that tricks you into
pasting a malicious command into Terminal, PowerShell, or the Windows Run box — **in the browser,
before you ever paste it**. It runs entirely locally; in this build nothing leaves your device and no
account is required.

## Status

**Gates 2a–2c done.**

- **2a — clipboard-write interception + warning (standalone).** A MAIN-world hook (`inject.js`) wraps
  `navigator.clipboard.writeText` and `document.execCommand('copy')` and forwards *command-shaped*
  payloads to the isolated content script (never blocking/altering the copy, nothing leaves the page).
  `content.js` matches remote-exec one-liners (`curl|bash`, `powershell … iex/DownloadString`,
  `osascript … do shell script`, `base64 -d | sh`, `mshta`, `certutil`/`bitsadmin`, `cmd /c …`,
  `/dev/tcp/…`) and throws an unmissable shadow-DOM warning with a one-click **Clear my clipboard**.
- **2b — page heuristics.** A dismissible **banner** for ClickFix *lure pages* ("verify you are human"
  + a shell/run instruction) and for *credential-phishing* (password field on an untrusted origin:
  public-IP, punycode, brand-on-wrong-domain, or plain http). Conservative, to avoid false positives.
- **2c — local-agent bridge (optional).** When paired with the Scouter agent, the clipboard warning is
  enriched with a **threat-intel verdict** (is the destination on a malware blocklist?) and a one-click
  **reversible, device-wide block** (`/etc/hosts` + blackhole route — protects the whole machine, not
  just the browser). Fully standalone when unpaired. See **Pairing** below.
- **2d — Firefox.** Cross-browser (Chromium `manifest.json` + Firefox `manifest.firefox.json`), no
  build step, no polyfill. See the Firefox load section below.
- **2e — packaging & store.** Icons (`tools/make-icons.py`, pure stdlib), `tools/pack.sh` builds
  store-ready Chrome + Firefox zips, plus `STORE.md` (listing + permission justifications) and
  `PRIVACY.md`.
- **Toolbar popup** — shows how many threats this browser has caught.

Phase 2 is feature-complete. (Later: surfacing browser threats as first-class agent/Mesh alerts — Phase 3.)

## Package for the stores

```
./tools/pack.sh      # -> dist/scouter-browser-defense-chrome-<v>.zip and ...-firefox-<v>.zip
```

Regenerate icons with `python3 tools/make-icons.py`. Submission copy + permission justifications are in
`STORE.md`; the privacy policy is `PRIVACY.md`.

## Pairing with the Scouter agent (optional)

1. In the agent, open `<agent URL>/api/ext/pair-info` in your browser
   (e.g. `http://127.0.0.1:7777/api/ext/pair-info`) to see the agent URL + a one-time pairing token.
2. Open the extension's **Options**, paste both, click **Save**, then **Test connection**.
3. The token is a persistent secret stored on your device; a web page can't reach these endpoints
   (loopback `Host` check + the unguessable `X-Scouter-Ext-Token` + the CORS-preflight barrier).
   Pass `--no-browser-ext` to the agent to disable the bridge entirely.

## Load it (Chrome / Edge / Brave — Chromium, MV3)

1. Go to `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select this `extension/` folder.
3. Visit any page. It's active everywhere (`<all_urls>`); the toolbar icon opens the status popup.

Requires Chromium with `world: "MAIN"` content scripts (Chrome/Edge 111+).

## Load it (Firefox — MV3, 128+)

Firefox needs its own manifest (it uses a background `scripts` event page where Chrome uses a
`service_worker`, plus a `browser_specific_settings` id). Both ship in this folder:

- **Temporary (dev):** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** →
  pick `manifest.firefox.json`.
- **Packaged:** build with `web-ext build --config-discovery=false` after copying `manifest.firefox.json`
  over `manifest.json`, or sign via AMO. (Keep `manifest.json` for Chromium; swap in the Firefox one
  only when packaging for Firefox.)

Requires Firefox **128+** (for `world: "MAIN"` content scripts). Note: in Firefox MV3, the
`http://127.0.0.1/*` host permission used for agent pairing is *optional* — grant it under the add-on's
permissions if the "Test connection" fails. The code itself is cross-browser (callback-style `chrome.*`
with a `browser.*` fallback for promise-only APIs).

## Test it

Open `test/clickfix-sim.html` (over `http://localhost` or `https://` so the clipboard API is a secure
context) and click the buttons. Buttons 1–3 must raise the red warning; button 4 (benign) must not.
The fixture loads `inject.js`/`content.js` directly so it works even before you install the extension.

## Privacy

`clipboardWrite` is used only for the **Clear my clipboard** button. The extension requests **no**
`clipboardRead` and in this standalone build makes **no** network requests — detection and the warning
are entirely in-page.
