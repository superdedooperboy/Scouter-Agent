// Scouter Web Guard — background service worker (MV3).
//
// Bridges the content scripts to the LOCAL Scouter agent over loopback HTTP, using a token the user
// pairs once (stored in chrome.storage). It holds no page content; it only forwards a threat's
// indicators (domain / ip / url) to the agent for a threat-intel verdict and, on request, a
// reversible block. When no agent is paired it returns {paired:false} and the extension stays fully
// standalone. The token lives here (the service worker), not in every page's content script.
"use strict";

const DEFAULTS = { agentUrl: "", agentToken: "" };

// Cross-browser storage read. Chrome MV3's chrome.storage.local.get() returns a Promise; Firefox's
// chrome.* namespace is callback-only (only browser.* returns Promises), so prefer browser.* there.
function cfg() {
  return new Promise(function (resolve) {
    try {
      if (typeof browser !== "undefined" && browser.storage && browser.storage.local) {
        browser.storage.local.get(DEFAULTS).then(
          function (v) { resolve(Object.assign({}, DEFAULTS, v || {})); },
          function () { resolve(Object.assign({}, DEFAULTS)); });
        return;
      }
      chrome.storage.local.get(DEFAULTS, function (v) {
        resolve(Object.assign({}, DEFAULTS, v || {}));
      });
    } catch (e) { resolve(Object.assign({}, DEFAULTS)); }
  });
}

function normUrl(u) {
  u = String(u || "").trim().replace(/\/+$/, "");
  if (u && !/^https?:\/\//i.test(u)) { u = "http://" + u; }
  return u;
}

async function agentFetch(path, opts) {
  const c = await cfg();
  const base = normUrl(c.agentUrl);
  if (!base || !c.agentToken) { return { paired: false }; }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch(base + path, Object.assign({
      signal: ctrl.signal,
      headers: Object.assign(
        { "X-Scouter-Ext-Token": c.agentToken, "Content-Type": "application/json" },
        (opts && opts.headers) || {})
    }, opts || {}));
    clearTimeout(timer);
    if (!r.ok) { return { paired: true, ok: false, status: r.status, error: "agent HTTP " + r.status }; }
    const j = await r.json().catch(() => ({}));
    return Object.assign({ paired: true }, j);
  } catch (e) {
    clearTimeout(timer);
    return { paired: true, ok: false, error: String((e && e.message) || e) };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) { return; }
  if (msg.type === "verdict") {
    agentFetch("/api/ext/verdict", { method: "POST", body: JSON.stringify({
      kind: msg.kind || "threat", url: msg.url || "", domain: msg.domain || "",
      ip: msg.ip || "", page_url: msg.page_url || "" }) }).then(sendResponse);
    return true;                         // keep the channel open for the async response
  }
  if (msg.type === "block") {
    agentFetch("/api/ext/block", { method: "POST", body: JSON.stringify({
      domain: msg.domain || "", ip: msg.ip || "" }) }).then(sendResponse);
    return true;
  }
  if (msg.type === "ping") {
    agentFetch("/api/ext/config", { method: "GET" }).then(sendResponse);
    return true;
  }
});

// First-run onboarding: open the welcome page once, on fresh install. Doubles as the standalone
// usage guide. (chrome.tabs.create for an own-extension URL needs no "tabs" permission.)
chrome.runtime.onInstalled.addListener(function (details) {
  if (details && details.reason === "install") {
    try { chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") }); } catch (e) { /* ignore */ }
  }
});
