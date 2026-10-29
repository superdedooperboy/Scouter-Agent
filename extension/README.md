# Scouter Web Guard (browser extension)

Phase 2 of Scouter's browser-threat monitoring. A Manifest V3 browser extension that catches the
**ClickFix** scam — a fake CAPTCHA / "verify you are human" / bogus-error page that tricks you into
pasting a malicious command into Terminal, PowerShell, or the Windows Run box — **in the browser,
before you ever paste it**. It runs entirely locally; in this build nothing leaves your device and no
account is required.

## Status

**Gate 2a (standalone detection + warning).** Done:

- **Clipboard-write interception** — a MAIN-world hook (`inject.js`) wraps `navigator.clipboard.writeText`
  and `document.execCommand('copy')` and forwards *command-shaped* payloads to the isolated content
  script. It never blocks or alters the copy and never sends anything off the page.
- **ClickFix heuristic + in-page warning** — `content.js` matches remote-exec one-liners (`curl|bash`,
  `powershell … iex/DownloadString`, `osascript … do shell script`, `base64 -d | sh`, `mshta`,
  `certutil`/`bitsadmin`, `cmd /c …`, `/dev/tcp/…`, etc.) and throws an unmissable, shadow-DOM warning
  with a one-click **Clear my clipboard**.
- **Toolbar popup** — shows how many scam commands this browser has caught.

Not yet (later gates): fake-CAPTCHA / credential-form page heuristics (2b); pairing with the local
Scouter agent for threat-intel verdicts + reversible blocking (2c); Firefox port (2d); packaging &
store/signing (2e).

## Load it (Chrome / Edge / Brave — Chromium, MV3)

1. Go to `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select this `extension/` folder.
3. Visit any page. It's active everywhere (`<all_urls>`); the toolbar icon opens the status popup.

Requires Chromium with `world: "MAIN"` content scripts (Chrome/Edge 111+).

## Test it

Open `test/clickfix-sim.html` (over `http://localhost` or `https://` so the clipboard API is a secure
context) and click the buttons. Buttons 1–3 must raise the red warning; button 4 (benign) must not.
The fixture loads `inject.js`/`content.js` directly so it works even before you install the extension.

## Privacy

`clipboardWrite` is used only for the **Clear my clipboard** button. The extension requests **no**
`clipboardRead` and in this standalone build makes **no** network requests — detection and the warning
are entirely in-page.
