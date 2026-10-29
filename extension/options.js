// Scouter Web Guard — options (pair with the local agent).
"use strict";
(function () {
  var url = document.getElementById("url");
  var tok = document.getElementById("tok");
  var msg = document.getElementById("msg");

  function show(text, cls) { msg.textContent = text; msg.className = "msg " + (cls || ""); }

  try {
    chrome.storage.local.get({ agentUrl: "", agentToken: "" }, function (v) {
      url.value = v.agentUrl || "";
      tok.value = v.agentToken || "";
    });
  } catch (e) { /* ignore */ }

  document.getElementById("save").addEventListener("click", function () {
    var u = url.value.trim(), t = tok.value.trim();
    try {
      chrome.storage.local.set({ agentUrl: u, agentToken: t }, function () {
        show(u && t ? "Saved. Click “Test connection” to verify." : "Saved (unpaired).", "ok");
      });
    } catch (e) { show("Could not save: " + e, "err"); }
  });

  document.getElementById("clear").addEventListener("click", function () {
    try {
      chrome.storage.local.set({ agentUrl: "", agentToken: "" }, function () {
        url.value = ""; tok.value = ""; show("Unpaired. The guard still runs standalone.", "ok");
      });
    } catch (e) { show("Could not clear: " + e, "err"); }
  });

  document.getElementById("test").addEventListener("click", function () {
    // Save first so the background uses the current values, then ping the agent.
    var u = url.value.trim(), t = tok.value.trim();
    if (!u || !t) { show("Enter the agent URL and token first.", "err"); return; }
    show("Testing…");
    try {
      chrome.storage.local.set({ agentUrl: u, agentToken: t }, function () {
        chrome.runtime.sendMessage({ type: "ping" }, function (r) {
          if (chrome.runtime.lastError) { show("No response from the extension worker.", "err"); return; }
          if (!r) { show("No response.", "err"); return; }
          if (!r.paired) { show("Not configured.", "err"); return; }
          if (r.ok === false) { show("Couldn’t reach the agent (" + (r.error || "error") + "). Check the URL and that the agent is running.", "err"); return; }
          show("✓ Connected to Scouter agent v" + (r.version || "?") + (r.armed ? " (armed)" : " (scouting)") + ".", "ok");
        });
      });
    } catch (e) { show("Error: " + e, "err"); }
  });
})();
