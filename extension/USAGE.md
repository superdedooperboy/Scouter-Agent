# Using Scouter Browser Defense

A short guide for everyday use. (Developers: see `README.md` for loading/packaging.)

## What it does

Scouter Browser Defense protects you from browser-delivered scams — with **no account and no setup**. Once
installed it runs on every page and only speaks up when something is dangerous.

It catches three things:

1. **ClickFix "paste this command" scams.** A page tells you to copy a command and paste it into
   Terminal, PowerShell, or the Windows Run box to "verify you are human" or "fix an error." The moment
   such a command is copied to your clipboard, you get a full-screen red warning **before you can paste
   it**, with a one-click **Clear my clipboard**.
2. **Fake "verify you are human" lure pages.** A dismissible banner flags the fake-CAPTCHA pages these
   scams use.
3. **Phishing sign-in pages.** A banner warns you when a page asks for a password on an untrustworthy
   web address (a look-alike domain, a raw IP address, a disguised/punycode name, or an insecure http
   connection).

## How to use it

There's nothing to do. Browse normally. When a warning appears:

- **Don't** paste or run anything a page told you to in order to "verify," "fix," or "update."
- Click **Clear my clipboard** (on the red warning) to neutralize a copied command.
- Close the tab.
- Click **×** to dismiss a banner once you've read it.

The toolbar icon opens a small popup showing how many threats it has caught.

## Privacy

Everything happens on your device. On its own the extension makes **no network requests**. It never
reads what *you* copy — only what a *web page* writes to your clipboard, and it never stores or sends
that. See `PRIVACY.md`.

## Optional: pair with a Scouter agent

If you run the free, open-source **Scouter agent** on your computer, you can pair the extension with it
(over your own computer only) to:

- confirm a flagged destination against **live malware blocklists**, and
- **block a malicious site across your whole device** (not just the browser) with one click — reversibly.

To pair: in the agent, open `http://127.0.0.1:<port>/api/ext/pair-info` to see your agent URL and a
pairing token, then paste both into the extension's **Options** and click **Save** → **Test connection**.
You can unpair any time; the guard keeps working standalone either way.
