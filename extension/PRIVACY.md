# Privacy Policy — Scouter Browser Defense

_Last updated: 2026-10-29_

Scouter Browser Defense is a browser extension that warns you about "ClickFix" paste-and-run command scams
and credential-phishing pages. It is built to protect your privacy, not to collect your data.

## What we collect
**Nothing.** The developer (Best Cyber Solutions) operates no servers for this extension, receives no
data from it, and uses no analytics, tracking, or advertising.

## How the extension processes data, on your device
- **Page content.** To detect a scam, the extension reads the current page's text and structure locally,
  in your browser. This never leaves the page.
- **Clipboard.** When a web page writes text to your clipboard, the extension checks whether that text
  looks like a command, so it can warn you before you paste it. It inspects this transiently and in the
  page only; it is **never stored and never transmitted**. The extension does not request clipboard-read
  permission and does not read clipboard contents you copy yourself.
- **Local settings.** A count of threats caught, and (only if you choose to pair with your own Scouter
  agent) the agent's local URL and pairing token, are saved on your device via the browser's extension
  storage. They are not synced to us.

## Network
In its standalone mode, the extension makes **no network requests**. If you explicitly pair it with a
Scouter agent running on your own computer, it sends a flagged page's domain/IP/URL to that agent **over
localhost only** (`127.0.0.1` / `localhost`) to get a threat-intel verdict and, at your request, block a
malicious site. That communication stays on your own device or network and never reaches the developer.

## Third parties
None. No data is shared with or sold to any third party.

## Your choices
You can unpair the agent at any time from the extension's Options, remove the extension to delete its
local storage, and decline the optional `localhost` host permission.

## Contact
Questions: security@bestcyber.co
