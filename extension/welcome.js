// Welcome page behavior. Loaded as an EXTERNAL script because Manifest V3's content security policy
// (script-src 'self') blocks inline <script>, which would otherwise leave the button inert.
document.getElementById("opts").addEventListener("click", function () {
  try {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL("options.html"));
    }
  } catch (e) {
    // As a last resort, navigate to the options page directly.
    try { window.location.href = chrome.runtime.getURL("options.html"); } catch (_) { /* ignore */ }
  }
});
