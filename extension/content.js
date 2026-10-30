// Scouter Browser Defense — isolated-world content script.
//
// Catches browser-delivered scams locally, with no agent and no account:
//   • ClickFix clipboard write (hard stop)  — a command-shaped payload hits the clipboard  -> MODAL
//   • ClickFix lure page (heads-up)         — "verify you are human" + run/paste instructions -> BANNER
//   • Credential phishing (heads-up)        — a password field on an untrusted origin        -> BANNER
// Warning severity matches confidence: the clipboard write is the hard signal (a focus-stealing
// modal); the page heuristics are corroborating (a dismissible top banner). Everything stays in the
// tab; this standalone build makes no network requests.
(function () {
  "use strict";

  // ============================ heuristics ============================

  // Remote-exec / ClickFix one-liner on the clipboard (tight, to avoid noise).
  var CMD = [
    /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b/i,
    /\b(ba|z)?sh\b\s+-c\b[^\n]{0,200}(curl|wget|http|base64)/i,
    /\bosascript\b[^\n]{0,160}(do\s+shell\s+script|-e\b)/i,
    /\b(powershell|pwsh)\b[^\n]{0,200}(-enc\b|-e\b|-nop\b|-w\s*hidden|iex|invoke-expression|downloadstring|frombase64string)/i,
    /\b(iex|invoke-expression)\b[^\n]{0,160}(http|downloadstring|net\.webclient|\$)/i,
    /\bmshta\b[^\n]{0,200}(https?:|javascript:|vbscript:)/i,
    /\b(certutil|bitsadmin)\b[^\n]{0,200}(https?:|-urlcache|-f\b|transfer)/i,
    /\bbase64\b[^\n]{0,80}(-d|--decode)[^\n]{0,80}\|\s*(ba|z)?sh\b/i,
    /\bregsvr32\b[^\n]{0,160}(scrobj|https?:)/i,
    /\bcmd(\.exe)?\s*\/c\b[^\n]{0,200}(curl|certutil|powershell|mshta|bitsadmin|start\s+https?:)/i,
    /\/dev\/tcp\/[0-9a-z.\-]+\/\d+/i,
    /\brundll32\b[^\n]{0,160}(javascript:|https?:|url\.dll)/i
  ];
  function looksLikeCommand(t) {
    if (typeof t !== "string") { return false; }
    var s = t.trim();
    if (s.length < 6) { return false; }
    for (var i = 0; i < CMD.length; i++) { if (CMD[i].test(s)) { return true; } }
    return false;
  }

  // ClickFix lure page = a "human verification" framing paired with an instruction to open/run a
  // shell. No legitimate CAPTCHA ever tells you to press Win+R or open Terminal, so the COMBINATION
  // is what fires (either signal alone is harmless).
  var LURE_HUMAN = [
    /verify (you['’]?re|that you are|you are) (a )?human/,
    /i['’]?m not a robot/,
    /human verification/,
    /are you (a )?human/,
    /confirm you (are|['’]re) human/,
    /verification (required|steps|code|id)\b/,
    /\bray id\b/,
    /checking your browser/
  ];
  var LURE_RUN = [
    /win(dows)?\s*\+\s*r\b/,
    /⊞\s*\+\s*r/,                 // ⊞ + R
    /windows\s*key/,
    /run dialog/,
    /open (the )?terminal/,
    /\bpowershell\b/,
    /\bcmd(\.exe)?\b/,
    /press\s*(ctrl|⌘|cmd|command)\s*\+\s*v/,  // ⌘/Ctrl + V, in a verification context
    /⌘\s*\+?\s*v/
  ];
  function detectLure(text) {
    var low = (text || "").toLowerCase();
    if (!low) { return false; }
    var human = false, run = false, i;
    for (i = 0; i < LURE_HUMAN.length; i++) { if (LURE_HUMAN[i].test(low)) { human = true; break; } }
    if (!human) { return false; }
    for (i = 0; i < LURE_RUN.length; i++) { if (LURE_RUN[i].test(low)) { run = true; break; } }
    return human && run;
  }

  // Credential phishing — deliberately CONSERVATIVE (richer reputation verdicts arrive when the
  // extension is paired with the Scouter agent). A password field plus one strong impersonation tell.
  var BRANDS = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "sharepoint.com", "onmicrosoft.com", "azure.com", "windows.net"],
    "office 365": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com"],
    "outlook": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "gmail": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "icloud": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "okta": ["okta.com", "oktacdn.com", "okta-emea.com"],
    "coinbase": ["coinbase.com"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"]
  };
  function isIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }
  function isPrivateIPv4(h) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (!m) { return false; }
    var a = +m[1], b = +m[2];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
           a === 127 || a === 0 || (a === 169 && b === 254) || a === 100 && b >= 64 && b <= 127;
  }
  function hostEndsWithAny(host, domains) {
    host = String(host || "").toLowerCase();
    for (var i = 0; i < domains.length; i++) {
      var d = domains[i].toLowerCase();
      if (host === d || host.endsWith("." + d)) { return true; }
    }
    return false;
  }
  function detectCredPhish() {
    try {
      if (!document.querySelector('input[type="password"]')) { return null; }
      var host = (location.hostname || "").toLowerCase();
      if (!host) { return null; }
      var isLocal = /^(localhost|0\.0\.0\.0|\[?::1\]?)$/.test(host) || host.endsWith(".local") ||
                    (isIPv4(host) && isPrivateIPv4(host));
      if (isLocal) { return null; }                       // local devices / dev servers are fine
      if (isIPv4(host)) { return { why: "a numeric IP address instead of a real site name", host: host }; }
      if (/(^|\.)xn--/.test(host)) { return { why: "a disguised (“punycode”) web address", host: host }; }
      var h1 = document.querySelector("h1");
      var title = ((document.title || "") + " " + (h1 ? (h1.textContent || "") : "")).toLowerCase();
      for (var brand in BRANDS) {
        if (!BRANDS.hasOwnProperty(brand)) { continue; }
        if (title.indexOf(brand) >= 0 && !hostEndsWithAny(host, BRANDS[brand])) {
          return { why: "it shows a “" + brand + "” sign-in, but this web address isn’t " +
                        brand + "’s", host: host, brand: brand };
        }
      }
      if (location.protocol === "http:") {
        return { why: "it asks for your password over an insecure (http) connection", host: host };
      }
      return null;
    } catch (e) { return null; }
  }

  // ============================ wiring ============================

  // Clipboard writes forwarded by the MAIN-world hook (inject.js) -> hard-stop modal.
  window.addEventListener("message", function (ev) {
    if (ev.source !== window) { return; }
    var d = ev.data;
    if (!d || d.__scouterWebGuard !== true || d.kind !== "clipboard") { return; }
    if (looksLikeCommand(d.text)) { onThreat("clipboard", { sample: String(d.text || "") }); }
  }, false);

  // Page scan: lure page + credential phishing. Runs on load and on DOM changes (SPAs / kits that
  // inject the instructions after a click), debounced, and stops once both have fired or after 20s.
  var scanned = { lurepage: false, credform: false };
  var obs = null, scanTimer = null;
  function pageText() {
    try {
      var b = document.body; if (!b) { return ""; }
      var t = b.innerText || b.textContent || "";
      return t.length > 20000 ? t.slice(0, 20000) : t;
    } catch (e) { return ""; }
  }
  function scanPage() {
    try {
      if (!scanned.lurepage && detectLure(pageText())) {
        scanned.lurepage = true; onThreat("lurepage", {});
      }
      if (!scanned.credform) {
        var c = detectCredPhish();
        if (c) { scanned.credform = true; onThreat("credform", c); }
      }
      if (scanned.lurepage && scanned.credform && obs) { obs.disconnect(); obs = null; }
    } catch (e) { /* never throw into the page */ }
  }
  function scheduleScan() { if (scanTimer) { return; } scanTimer = setTimeout(function () { scanTimer = null; scanPage(); }, 400); }
  function startScan() {
    scanPage();
    try {
      obs = new MutationObserver(scheduleScan);
      obs.observe(document.documentElement || document, { childList: true, subtree: true, characterData: true });
      setTimeout(function () { if (obs) { obs.disconnect(); obs = null; } }, 20000);
    } catch (e) { /* ignore */ }
  }
  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", startScan); }
  else { startScan(); }

  // ============================ warnings ============================

  var lastModal = 0;
  function onThreat(kind, opts) {
    try {
      if (kind === "clipboard" || kind === "lurepage") { bump(); }
      if (kind === "clipboard") {
        var now = Date.now();
        if (now - lastModal < 4000) { return; }        // one modal per burst
        lastModal = now;
        removeBanner();                                 // a hard stop supersedes a heads-up banner
        showModal(opts.sample || "");
      } else if (kind === "lurepage") {
        showBanner("lurepage", opts);
      } else if (kind === "credform") {
        showBanner("credform", opts);
      }
    } catch (e) { /* ignore */ }
  }

  var MODAL_ID = "scouter-browser-defense-host";
  var BANNER_ID = "scouter-browser-defense-banner";

  function mkShadow(id) {
    var old = document.getElementById(id); if (old) { old.remove(); }
    var host = document.createElement("div");
    host.id = id; host.setAttribute("style", "all:initial");
    var shadow = host.attachShadow ? host.attachShadow({ mode: "closed" }) : host;
    return { host: host, shadow: shadow };
  }
  function btnStyle(bg, fg) {
    return ["appearance:none", "border:0", "border-radius:8px", "padding:9px 16px", "font-size:13px",
            "font-weight:600", "cursor:pointer", "background:" + bg, "color:" + fg].join(";");
  }

  function showModal(sample) {
    var root = document.documentElement; if (!root) { return; }
    var m = mkShadow(MODAL_ID), shadow = m.shadow, host = m.host;
    var wrap = document.createElement("div");
    wrap.setAttribute("style", ["position:fixed", "inset:0", "z-index:2147483647",
      "background:rgba(10,10,14,.72)", "backdrop-filter:blur(2px)", "display:flex",
      "align-items:flex-start", "justify-content:center",
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"].join(";"));
    var card = document.createElement("div");
    card.setAttribute("style", ["margin-top:8vh", "max-width:560px", "width:calc(100% - 32px)",
      "background:#17171c", "color:#f4f4f6", "border:1px solid #5b1a1a", "border-top:4px solid #e5484d",
      "border-radius:12px", "box-shadow:0 20px 60px rgba(0,0,0,.5)", "padding:20px 22px", "box-sizing:border-box"].join(";"));
    var h = el("div", "font-size:18px;font-weight:700;color:#ff6b6e;margin:0 0 8px", "⚠️  Stop — this looks like a scam");
    var p1 = el("div", "font-size:14px;line-height:1.5;margin:0 0 10px;color:#e6e6ea",
      "This page just copied a command to your clipboard. If it told you to paste it into Terminal, " +
      "PowerShell, or the Windows Run box to “verify you are human,” “fix an error,” or " +
      "“install an update” — don’t. That command can install malware.");
    var label = el("div", "font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#9a9aa3;margin:0 0 4px", "What was copied");
    var code = el("div", ["font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace", "font-size:12.5px",
      "background:#0c0c10", "color:#ffd7d7", "border:1px solid #2a2a31", "border-radius:8px", "padding:10px 12px",
      "margin:0 0 14px", "max-height:120px", "overflow:auto", "white-space:pre-wrap", "word-break:break-all"].join(";"),
      sample.length > 400 ? sample.slice(0, 400) + "…" : sample);
    var tips = el("div", "font-size:13px;line-height:1.6;margin:0 0 16px;color:#cfcfd6;white-space:pre-line",
      "• Do not paste it anywhere.\n• Close this tab.\n• A real website never asks you to run a command to prove you’re human.");
    var row = el("div", "display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap");
    var clearBtn = el("button", btnStyle("#2a2a31", "#f4f4f6"), "Clear my clipboard");
    clearBtn.addEventListener("click", function () {
      try { if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText("").catch(function () {}); } } catch (e) {}
      close();
    });
    var okBtn = el("button", btnStyle("#e5484d", "#fff"), "Got it, close");
    okBtn.addEventListener("click", close);
    function close() { try { host.remove(); } catch (e) {} }
    row.appendChild(clearBtn); row.appendChild(okBtn);
    [h, p1, label, code, tips, row].forEach(function (n) { card.appendChild(n); });
    wrap.appendChild(card);
    wrap.addEventListener("click", function (e) { if (e.target === wrap) { close(); } });
    shadow.appendChild(wrap); root.appendChild(host);
    try { okBtn.focus(); } catch (e) {}
    agentEnrich(card, firstTargetFromCommand(sample));   // if a local agent is paired: verdict + block
  }

  function removeBanner() { var b = document.getElementById(BANNER_ID); if (b) { b.remove(); } }
  function showBanner(kind, opts) {
    var root = document.documentElement; if (!root) { return; }
    if (document.getElementById(MODAL_ID)) { return; }   // a hard-stop modal already covers it
    if (document.getElementById(BANNER_ID)) { return; }  // one banner at a time (first/most severe)
    var red = kind === "lurepage";
    var accent = red ? "#e5484d" : "#f5a524";
    var msg = red
      ? "This page looks like a “ClickFix” scam — it may ask you to paste a command to “verify you are human.” Don’t run anything it tells you to."
      : "Possible phishing: this page asks for a password, but " + (opts && opts.why ? opts.why : "the web address looks untrustworthy") + ". Don’t enter your password unless you’re sure this site is genuine.";
    var m = mkShadow(BANNER_ID), shadow = m.shadow, host = m.host;
    var bar = el("div", ["position:fixed", "top:0", "left:0", "right:0", "z-index:2147483646",
      "background:#17171c", "color:#f4f4f6", "border-bottom:1px solid #2a2a31", "border-top:4px solid " + accent,
      "box-shadow:0 8px 24px rgba(0,0,0,.35)", "padding:11px 16px", "display:flex", "align-items:center",
      "gap:12px", "font:13.5px/1.45 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"].join(";"));
    var ic = el("div", "font-size:16px;flex:0 0 auto", "⚠️");
    var tx = el("div", "flex:1 1 auto;color:#ededf0", msg);
    var bstrong = el("b", "color:" + (red ? "#ff8a8d" : "#ffcf7a"), red ? "Scouter: likely scam page. " : "Scouter: possible phishing. ");
    tx.insertBefore(bstrong, tx.firstChild);
    var x = el("button", btnStyle("transparent", "#b9b9c2") + ";padding:6px 10px;font-size:18px;line-height:1", "×");
    x.setAttribute("aria-label", "Dismiss");
    x.addEventListener("click", function () { try { host.remove(); } catch (e) {} });
    bar.appendChild(ic); bar.appendChild(tx); bar.appendChild(x);
    shadow.appendChild(bar); root.appendChild(host);
  }

  function el(tag, style, text) {
    var n = document.createElement(tag);
    if (style) { n.setAttribute("style", style); }
    if (text != null) { n.textContent = text; }
    return n;
  }

  // ---- optional local-agent bridge (threat-intel verdict + reversible device-wide block) ----
  function safeHref() { try { return location.href || ""; } catch (e) { return ""; } }
  function firstTargetFromCommand(sample) {
    var m = /\bhttps?:\/\/[^\s'"`|;<>)]+/i.exec(sample || "");
    if (m) {
      try {
        var u = new URL(m[0]);
        var host = u.hostname || "";
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { return { url: m[0], ip: host }; }
        return { url: m[0], domain: host };
      } catch (e) { /* fall through */ }
    }
    var ipm = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(sample || "");
    if (ipm) { return { ip: ipm[0] }; }
    return {};
  }
  function agentAsk(payload) {
    return new Promise(function (resolve) {
      try {
        if (!(window.chrome && chrome.runtime && chrome.runtime.sendMessage)) { resolve(null); return; }
        chrome.runtime.sendMessage(payload, function (r) {
          if (chrome.runtime.lastError) { resolve(null); return; }
          resolve(r || null);
        });
      } catch (e) { resolve(null); }
    });
  }
  function agentEnrich(card, target) {
    if (!card || !(target && (target.domain || target.ip || target.url))) { return; }
    agentAsk(Object.assign({ type: "verdict", kind: "clickfix", page_url: safeHref() }, target)).then(function (r) {
      if (!r || !r.paired) { return; }                 // standalone / not paired → leave the warning as-is
      var tgt = (r.target && (r.target.domain || r.target.ip)) || target.domain || target.ip || "";
      var line = el("div", "margin:12px 0 2px;font-size:12.5px;line-height:1.45",
        r.verdict === "malicious"
          ? "✓ Scouter confirms " + tgt + " is on a malware blocklist (" + (r.feed || "threat intel") + ")."
          : "Your Scouter agent has no record of " + (tgt || "this site") + " — stay cautious.");
      line.style.color = r.verdict === "malicious" ? "#ff9c9e" : "#9a9aa3";
      card.appendChild(line);
      if (r.blocked && r.blocked.length) {
        card.appendChild(el("div", "font-size:12.5px;color:#7ee0a1;margin-top:2px",
          "✓ Scouter blocked " + tgt + " on this device (undo in Scouter → Response)."));
      } else if (r.can_block && tgt) {
        var btn = el("button", btnStyle("#2f6fed", "#fff") + ";margin-top:10px", "Block " + tgt + " on my device");
        btn.addEventListener("click", function () {
          btn.disabled = true; btn.textContent = "Blocking…";
          agentAsk({ type: "block", domain: (r.target && r.target.domain) || target.domain || "",
                     ip: (r.target && r.target.ip) || target.ip || "" }).then(function (b) {
            var okb = b && b.ok;
            btn.textContent = okb ? "✓ Blocked " + tgt
              : "Couldn’t block" + (b && b.results && b.results[0] && b.results[0].error ? ": " + b.results[0].error : "");
            btn.style.background = okb ? "#2fa84f" : "#6b2b2b";
          });
        });
        card.appendChild(btn);
      }
    });
  }

  // Local counter shown in the toolbar popup. Best-effort.
  function bump() {
    if (!(window.chrome && chrome.storage && chrome.storage.local)) { return; }
    try {
      chrome.storage.local.get({ blocked: 0 }, function (v) {
        var host = ""; try { host = location.hostname || ""; } catch (e) {}
        chrome.storage.local.set({ blocked: (v.blocked || 0) + 1, lastHost: host, lastTs: Date.now() });
      });
    } catch (e) { /* ignore */ }
  }
})();
