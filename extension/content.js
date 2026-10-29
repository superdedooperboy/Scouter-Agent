// Scouter Web Guard — isolated-world content script.
//
// Receives command-shaped clipboard payloads forwarded by the MAIN-world hook (inject.js), applies
// the real ClickFix heuristic, and — entirely locally, with no agent and no account — throws an
// unmissable in-page warning the moment a scam command hits the clipboard, *before* the user pastes
// it. Everything here stays in the tab; nothing is sent anywhere in this (standalone) build.
(function () {
  "use strict";

  // --- heuristic: does this look like a remote-exec / ClickFix one-liner? (tight, to avoid noise) ---
  var CMD = [
    /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b/i,                  // download | shell
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

  // --- listen for forwarded clipboard writes from the MAIN world ---
  window.addEventListener("message", function (ev) {
    if (ev.source !== window) { return; }
    var d = ev.data;
    if (!d || d.__scouterWebGuard !== true || d.kind !== "clipboard") { return; }
    if (looksLikeCommand(d.text)) { warn(d.text, d.via); }
  }, false);

  // --- the warning (isolated in a shadow root so the page can't style or script it) ---
  var HOST_ID = "scouter-web-guard-host";
  var lastWarn = 0;

  function warn(sample, via) {
    var now = Date.now();
    if (now - lastWarn < 4000) { return; }      // one warning per burst (kits copy repeatedly)
    lastWarn = now;
    try { showOverlay(String(sample || "")); } catch (e) { /* never throw into the page */ }
    try { bump(); } catch (e) { /* storage is best-effort */ }
  }

  function showOverlay(sample) {
    var root = document.documentElement;        // present even at document_start (body may not be)
    if (!root) { return; }
    var existing = document.getElementById(HOST_ID);
    if (existing) { existing.remove(); }
    var host = document.createElement("div");
    host.id = HOST_ID;
    host.setAttribute("style", "all:initial");
    var shadow = host.attachShadow ? host.attachShadow({ mode: "closed" }) : host;

    var wrap = document.createElement("div");
    wrap.setAttribute("style", [
      "position:fixed", "inset:0", "z-index:2147483647",
      "background:rgba(10,10,14,.72)", "backdrop-filter:blur(2px)",
      "display:flex", "align-items:flex-start", "justify-content:center",
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
    ].join(";"));

    var card = document.createElement("div");
    card.setAttribute("style", [
      "margin-top:8vh", "max-width:560px", "width:calc(100% - 32px)",
      "background:#17171c", "color:#f4f4f6", "border:1px solid #5b1a1a",
      "border-top:4px solid #e5484d", "border-radius:12px",
      "box-shadow:0 20px 60px rgba(0,0,0,.5)", "padding:20px 22px", "box-sizing:border-box"
    ].join(";"));

    var h = document.createElement("div");
    h.setAttribute("style", "font-size:18px;font-weight:700;color:#ff6b6e;margin:0 0 8px;display:flex;align-items:center;gap:8px");
    h.textContent = "⚠️  Stop — this looks like a scam";

    var p1 = document.createElement("div");
    p1.setAttribute("style", "font-size:14px;line-height:1.5;margin:0 0 10px;color:#e6e6ea");
    p1.textContent = "This page just copied a command to your clipboard. If it told you to paste it " +
      "into Terminal, PowerShell, or the Windows Run box to “verify you are human,” “fix " +
      "an error,” or “install an update” — don’t. That command can install malware.";

    var label = document.createElement("div");
    label.setAttribute("style", "font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:#9a9aa3;margin:0 0 4px");
    label.textContent = "What was copied";

    var code = document.createElement("div");
    code.setAttribute("style", [
      "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace", "font-size:12.5px",
      "background:#0c0c10", "color:#ffd7d7", "border:1px solid #2a2a31", "border-radius:8px",
      "padding:10px 12px", "margin:0 0 14px", "max-height:120px", "overflow:auto",
      "white-space:pre-wrap", "word-break:break-all"
    ].join(";"));
    code.textContent = sample.length > 400 ? sample.slice(0, 400) + "…" : sample;

    var tips = document.createElement("div");
    tips.setAttribute("style", "font-size:13px;line-height:1.6;margin:0 0 16px;color:#cfcfd6");
    tips.textContent = "• Do not paste it anywhere.\n• Close this tab.\n• A real website never asks you to run a command to prove you’re human.";
    tips.style.whiteSpace = "pre-line";

    var row = document.createElement("div");
    row.setAttribute("style", "display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap");

    var clearBtn = document.createElement("button");
    clearBtn.setAttribute("style", btnStyle("#2a2a31", "#f4f4f6"));
    clearBtn.textContent = "Clear my clipboard";
    clearBtn.addEventListener("click", function () {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText("").catch(function () {});   // neutralize the pasted command
        }
      } catch (e) { /* best-effort */ }
      close();
    });

    var okBtn = document.createElement("button");
    okBtn.setAttribute("style", btnStyle("#e5484d", "#fff"));
    okBtn.textContent = "Got it, close";
    okBtn.addEventListener("click", close);

    function close() { try { host.remove(); } catch (e) {} }

    row.appendChild(clearBtn);
    row.appendChild(okBtn);
    card.appendChild(h);
    card.appendChild(p1);
    card.appendChild(label);
    card.appendChild(code);
    card.appendChild(tips);
    card.appendChild(row);
    wrap.appendChild(card);
    wrap.addEventListener("click", function (e) { if (e.target === wrap) { close(); } });
    shadow.appendChild(wrap);
    root.appendChild(host);
    try { okBtn.focus(); } catch (e) {}
  }

  function btnStyle(bg, fg) {
    return [
      "appearance:none", "border:0", "border-radius:8px", "padding:9px 16px",
      "font-size:13px", "font-weight:600", "cursor:pointer", "background:" + bg, "color:" + fg
    ].join(";");
  }

  // --- local detection counter (shown in the toolbar popup); best-effort, never required ---
  function bump() {
    if (!(window.chrome && chrome.storage && chrome.storage.local)) { return; }
    chrome.storage.local.get({ blocked: 0, lastHost: "" }, function (v) {
      var host = "";
      try { host = location.hostname || ""; } catch (e) {}
      chrome.storage.local.set({ blocked: (v.blocked || 0) + 1, lastHost: host, lastTs: Date.now() });
    });
  }
})();
