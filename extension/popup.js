// Toolbar popup: show how many ClickFix clipboard scams this browser has caught.
(function () {
  "use strict";
  function render(v) {
    var c = document.getElementById("count");
    var m = document.getElementById("meta");
    if (c) { c.textContent = String(v.blocked || 0); }
    if (m && v.blocked && v.lastHost) {
      var when = v.lastTs ? new Date(v.lastTs).toLocaleString() : "";
      m.textContent = "Last: " + v.lastHost + (when ? " · " + when : "");
    }
  }
  try {
    chrome.storage.local.get({ blocked: 0, lastHost: "", lastTs: 0 }, render);
  } catch (e) {
    render({ blocked: 0 });
  }
})();
