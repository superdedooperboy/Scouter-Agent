// Scouter Web Guard — MAIN-world hook.
//
// A content script runs in an *isolated* world and cannot override the page's own objects, so this
// file is injected into the PAGE's JavaScript world (manifest `world: "MAIN"`). Its only job is to
// notice when the page puts a *command-shaped* payload on the clipboard — the hallmark of the
// "ClickFix" scam, where a fake CAPTCHA / "verify you are human" page tells the visitor to paste a
// command into Terminal or the Run box.
//
// Privacy + safety contract:
//   • It NEVER blocks or alters the copy — legitimate "copy this command" buttons keep working.
//   • It NEVER sends anything off the page. It only forwards a command-shaped payload to the
//     extension's own isolated content script, in the SAME tab, via window.postMessage. The
//     clipboard text never leaves this tab, and ordinary copies (prose, URLs, code) are filtered
//     out here before they are ever forwarded.
//   • It must never break the page: every hook is wrapped and always calls through to the original.
(function () {
  "use strict";
  var TAG = "__scouterWebGuardInjected";
  if (window[TAG]) { return; }                 // idempotent: all_frames + any re-injection
  window[TAG] = true;

  // Cheap pre-filter. Only a payload containing a shell/command-ish token is forwarded, so the vast
  // majority of copies never leave the page world. The isolated side applies the real heuristic.
  var HINT = new RegExp(
    "\\b(curl|wget|bash|zsh|powershell|pwsh|iex|invoke-expression|mshta|msiexec|certutil|" +
    "bitsadmin|osascript|base64|regsvr32|rundll32|/dev/tcp)\\b|\\bcmd(\\.exe)?\\s*/c\\b|" +
    "\\bsh\\b\\s*$|\\bWin\\s*\\+\\s*R\\b", "i");

  function forward(text, via) {
    try {
      if (typeof text !== "string") { return; }
      if (text.length < 6 || text.length > 20000) { return; }
      if (!HINT.test(text)) { return; }
      window.postMessage({ __scouterWebGuard: true, kind: "clipboard", via: via, text: text }, "*");
    } catch (e) { /* instrumentation must never throw into the page */ }
  }

  // 1) navigator.clipboard.writeText(...) — the modern async clipboard API, the ClickFix staple.
  try {
    var clip = navigator.clipboard;
    if (clip && typeof clip.writeText === "function") {
      var origWrite = clip.writeText.bind(clip);
      clip.writeText = function (text) {
        forward(text, "writeText");
        return origWrite(text);                // transparent: identical promise + behavior
      };
    }
  } catch (e) { /* ignore */ }

  // 2) document.execCommand('copy') — the classic hidden-textarea copy still used by many kits.
  try {
    var origExec = document.execCommand.bind(document);
    document.execCommand = function (cmd) {
      try {
        if (String(cmd).toLowerCase() === "copy") {
          var t = "";
          var ae = document.activeElement;
          if (ae && (ae.tagName === "TEXTAREA" || ae.tagName === "INPUT") &&
              typeof ae.value === "string") {
            var a = ae.selectionStart, b = ae.selectionEnd;
            t = (a != null && b != null && b > a) ? ae.value.substring(a, b) : ae.value;
          }
          if (!t && window.getSelection) { t = String(window.getSelection() || ""); }
          forward(t, "execCommand");
        }
      } catch (e) { /* ignore */ }
      return origExec.apply(document, arguments);
    };
  } catch (e) { /* ignore */ }
})();
