// ============================================================
//  Visa Automator — background service worker (MV3)
//  Kept intentionally tiny: no run state lives here (the worker
//  is killed after ~30s idle). It only:
//    1) relays the toolbar click to the page as a toggle, and
//    2) offers a best-effort payment-URL fallback (R6 step 4)
//       for gateways that open in the SAME tab. New-tab gateways
//       and cross-origin URLs require adding the gateway host to
//       host_permissions (see manifest placeholder).
// ============================================================

// (1) Toolbar icon toggles the panel.
chrome.action.onClicked.addListener((tab) => {
    if (!tab || tab.id == null) return;
    chrome.tabs.sendMessage(tab.id, { action: "toggle_widget" }, () => {
        void chrome.runtime.lastError; // suppress "no receiver" on restricted pages
    });
});

// (2) Payment-URL fallback. `changeInfo.url` is only populated for URLs the
//     extension has host permission for (or with the "tabs" permission), so
//     this reliably catches only same-site payment paths today; it lights up
//     automatically once a gateway host is added to host_permissions.
const PAYMENT_HINT = /(payment|gateway|checkout|dgepay|webview|sslcommerz|aamarpay|bkash|nagad|redirect)/i;

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    const url = changeInfo && changeInfo.url;
    if (!url || !PAYMENT_HINT.test(url)) return;
    chrome.tabs.sendMessage(tabId, { action: "payment_url", url }, () => {
        void chrome.runtime.lastError;
    });
});

// (3) Human-attention relay. The page's attention module can't focus its own
//     window or raise an OS notification, so it asks us to. We bring the
//     requesting tab + its window to the front and pop a sticky desktop
//     notification so a coworker solves the Cloudflare check without watching
//     the tab. NOTE: this only draws attention — it never solves anything.
const NOTIF_ID = "va-attention";
let attentionTarget = null; // { tabId, windowId } of the last tab that called

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.action) return;

    if (msg.action === "attention") {
        const tab = sender && sender.tab;
        if (tab && tab.id != null) {
            attentionTarget = { tabId: tab.id, windowId: tab.windowId };
            try { chrome.tabs.update(tab.id, { active: true }, () => { void chrome.runtime.lastError; }); } catch (_) {}
            if (tab.windowId != null) {
                try { chrome.windows.update(tab.windowId, { focused: true, drawAttention: true }, () => { void chrome.runtime.lastError; }); } catch (_) {}
            }
        }
        try {
            chrome.notifications.create(NOTIF_ID, {
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: msg.title || "IVAC SLOT AUTOMATION PRO — action needed",
                message: msg.reason || "Human verification needed on the IVAC tab.",
                priority: 2,
                requireInteraction: true
            }, () => { void chrome.runtime.lastError; });
        } catch (_) {}
        sendResponse && sendResponse({ ok: true });
        return;
    }

    if (msg.action === "attention_clear") {
        try { chrome.notifications.clear(NOTIF_ID, () => { void chrome.runtime.lastError; }); } catch (_) {}
        sendResponse && sendResponse({ ok: true });
        return;
    }
});

// Clicking the notification jumps straight to the waiting tab.
chrome.notifications.onClicked.addListener((id) => {
    if (id !== NOTIF_ID || !attentionTarget) return;
    try { chrome.tabs.update(attentionTarget.tabId, { active: true }, () => { void chrome.runtime.lastError; }); } catch (_) {}
    if (attentionTarget.windowId != null) {
        try { chrome.windows.update(attentionTarget.windowId, { focused: true }, () => { void chrome.runtime.lastError; }); } catch (_) {}
    }
    try { chrome.notifications.clear(NOTIF_ID, () => { void chrome.runtime.lastError; }); } catch (_) {}
});

// ============================================================
//  (4) License relay + periodic (~24h) online re-validation (M4).
//  The content-script license client (src/license.js) never fetches the
//  API directly — it relays through here. This worker owns the API base
//  URL + host permission and runs the online re-check on a chrome.alarms
//  schedule, so a revoked/expired license is caught even when no IVAC tab
//  is open. It holds NO private keys and NO database access — it only
//  forwards signed responses; signatures are verified in the content
//  script against the embedded public key.
// ============================================================

// ⚠ DEPLOY: point this at your deployed licensing backend, and keep it in
//   sync with "host_permissions" in manifest.json (both must be updated).
const LICENSE_API_BASE = "https://ivac-bd.vercel.app";

const LICENSE_CACHE_KEY = "ivacLicenseCache";
const LICENSE_INSTALL_KEY = "ivacInstallId";
const LICENSE_DEVICE_KEY = "ivacDeviceId";
const LICENSE_BROWSER_KEY = "ivacBrowserId";
const LICENSE_BROWSER_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LICENSE_ALARM = "license_revalidate";
const LICENSE_DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const LICENSE_HARD_CODES = ["REVOKED", "BLOCKED", "SUSPENDED", "EXPIRED", "INVALID_KEY", "NOT_FOUND"];
const LICENSE_ENDPOINTS = new Set([
    "/api/license/activate",
    "/api/license/validate",
    "/api/license/deactivate-device",
    "/api/license/status",
]);

function licGet(key) {
    return new Promise((resolve) => {
        try { chrome.storage.local.get(key, (r) => resolve((r && r[key]) || null)); }
        catch (_) { resolve(null); }
    });
}
function licSet(key, val) { try { chrome.storage.local.set({ [key]: val }); } catch (_) {} }
function licRemove(key) { try { chrome.storage.local.remove(key); } catch (_) {} }

async function licenseFetch(endpoint, body) {
    if (!LICENSE_ENDPOINTS.has(endpoint)) return { ok: false, error: "Unknown endpoint." };
    try {
        const res = await fetch(LICENSE_API_BASE + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {}),
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}
        return { ok: res.ok, status: res.status, data };
    } catch (_) {
        return { ok: false, error: "Cannot reach the licensing server." };
    }
}

// OTP relay (same backend host as the license API). The content script polls
// this while it waits on the OTP page; the OTP itself is pushed up by the
// separate Android app, never by the extension — so only /poll is whitelisted.
const OTP_ENDPOINTS = new Set(["/api/otp/poll", "/api/otp/ack"]);
async function otpFetch(endpoint, body) {
    if (!OTP_ENDPOINTS.has(endpoint)) return { ok: false, error: "Unknown endpoint." };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    try {
        const res = await fetch(LICENSE_API_BASE + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {}),
            signal: controller.signal,
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}
        const retry = Number(res.headers.get("Retry-After") || 0);
        return { ok: res.ok, status: res.status, data, retryAfterMs: retry > 0 ? retry * 1000 : 0 };
    } catch (err) {
        return { ok: false, error: err && err.name === "AbortError" ? "timeout" : "offline" };
    } finally {
        clearTimeout(timeout);
    }
}

// CAPTCHA solver relay (2Captcha createTask / getTaskResult). Under MV3 a
// content script cannot POST cross-origin to api.2captcha.com (CORS + the
// page's CSP block it), so the service worker — which holds the
// api.2captcha.com host permission — makes the call and returns the JSON.
// Only the two solver endpoints are whitelisted.
//
// The 2Captcha key is NOT shipped in the extension. The worker fetches it once
// per browser session from the licensing backend (gated on an active license),
// caches it in chrome.storage.session (in-memory, never on disk, and not
// readable by content scripts), and injects it as `clientKey` on every solve —
// so the content script never sees the key, and per-solve latency is unchanged
// (the direct worker→2Captcha call stays the only network hop while solving).
const CAPTCHA_BASE = "https://api.2captcha.com";
const CAPTCHA_ENDPOINTS = new Set(["/createTask", "/getTaskResult"]);
const CAPTCHA_KEY_ENDPOINT = "/api/captcha/key";
const CAPTCHA_KEY_SESSION = "ivacCaptchaKey";

function sessGet(key) {
    return new Promise((resolve) => {
        try {
            if (!chrome.storage.session) { resolve(null); return; }
            chrome.storage.session.get(key, (r) => resolve((r && r[key]) || null));
        } catch (_) { resolve(null); }
    });
}
function sessSet(key, val) { try { chrome.storage.session && chrome.storage.session.set({ [key]: val }); } catch (_) {} }

// Fetch the key once (coalescing concurrent callers), cache it, reuse it.
// Returns "" when solving isn't configured or the device isn't licensed —
// captchaFetch then reports {configured:false} so the caller falls back to
// the manual Cloudflare flow instead of hammering 2Captcha with no key.
let _captchaKeyInflight = null;
async function getCaptchaKey() {
    const cached = await sessGet(CAPTCHA_KEY_SESSION);
    if (cached && cached.key) return cached.key;
    if (_captchaKeyInflight) return _captchaKeyInflight;
    _captchaKeyInflight = (async () => {
        const cache = await licGet(LICENSE_CACHE_KEY);
        const install = await licGet(LICENSE_INSTALL_KEY);
        if (!cache || !cache.licenseId || !install) return "";
        // Send the durable browserId too, so this gate resolves the same
        // activation row as activate/validate (and survives a reinstall).
        const browser = await licGet(LICENSE_BROWSER_KEY);
        const body = { licenseId: cache.licenseId, installationId: install };
        if (browser && LICENSE_BROWSER_ID_RE.test(browser)) body.browserId = browser;
        try {
            const res = await fetch(LICENSE_API_BASE + CAPTCHA_KEY_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            let data = null;
            try { data = await res.json(); } catch (_) {}
            if (res.ok && data && data.success !== false && data.apiKey) {
                sessSet(CAPTCHA_KEY_SESSION, { key: data.apiKey, at: Date.now() });
                return data.apiKey;
            }
        } catch (_) { /* offline / unreachable → treat as not-configured */ }
        return "";
    })();
    try { return await _captchaKeyInflight; } finally { _captchaKeyInflight = null; }
}

async function captchaFetch(endpoint, body) {
    if (!CAPTCHA_ENDPOINTS.has(endpoint)) return { ok: false, error: "Unknown endpoint." };
    const key = await getCaptchaKey();
    if (!key) return { ok: false, error: "CAPTCHA solving is not configured.", configured: false };
    const payload = Object.assign({}, body || {}, { clientKey: key });
    try {
        const res = await fetch(CAPTCHA_BASE + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}
        return { ok: res.ok, status: res.status, data };
    } catch (_) {
        return { ok: false, error: "Cannot reach the CAPTCHA solver." };
    }
}

// ============================================================
//  (5) Proxy routing relay — SHOWCASE / dynamic routing.
//  The Run tab's "Proxy IP" card is fed by the licensing backend, so the
//  IP in its PROXY_IP environment variable and exposes it at
//  POST /api/proxy/ip; POST /api/proxy/shift rotates to the next one.
//  If the backend is unreachable (or has no IP configured) the content script
//  Set PROXY_IP_ENV below to pin an IP locally (mirrors the backend env var)
// ============================================================
const PROXY_API_BASE = LICENSE_API_BASE; // same host + host_permission as the license API
const PROXY_ENDPOINTS = new Set(["/api/proxy/ip", "/api/proxy/shift"]);
const PROXY_IP_ENV = "";                 

const PROXY_IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
function isProxyIPv4(s) { return typeof s === "string" && PROXY_IPV4_RE.test(s.trim()); }

async function proxyFetch(endpoint, body) {
    if (!PROXY_ENDPOINTS.has(endpoint)) return { ok: false, error: "Unknown endpoint." };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    try {
        const res = await fetch(PROXY_API_BASE + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {}),
            signal: controller.signal,
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}
        return { ok: res.ok, status: res.status, data };
    } catch (err) {
        return { ok: false, error: err && err.name === "AbortError" ? "timeout" : "offline" };
    } finally {
        clearTimeout(timeout);
    }
}

function proxyResult(resp, fallbackError) {
    const data = resp && resp.data;
    const ip = data && (data.ip || data.proxyIp);
    if (resp && resp.ok && data && data.success !== false && isProxyIPv4(ip)) {
        return { ok: true, ip: ip.trim(), source: "server", region: data.region || "", operator: data.operator || "" };
    }
    return { ok: false, error: (resp && resp.error) || fallbackError };
}

// Current proxy IP: local env override → backend → none (caller falls back).
async function proxyIpFetch() {
    if (isProxyIPv4(PROXY_IP_ENV)) return { ok: true, ip: PROXY_IP_ENV.trim(), source: "env" };
    return proxyResult(await proxyFetch("/api/proxy/ip", {}), "no_ip");
}

// Rotate to the next proxy IP (backend /api/proxy/shift). Wired up and ready,
// but deliberately NOT called by the panel yet — point the UI at it when the
// backend endpoint is live.
async function proxyShiftIp(body) {
    if (isProxyIPv4(PROXY_IP_ENV)) return { ok: true, ip: PROXY_IP_ENV.trim(), source: "env" };
    return proxyResult(await proxyFetch("/api/proxy/shift", body), "shift_failed");
}

// Fire-and-forget online re-check driven by the alarm (works with no tab open).
async function revalidateLicense() {
    const cache = await licGet(LICENSE_CACHE_KEY);
    const install = await licGet(LICENSE_INSTALL_KEY);
    if (!cache || !cache.token || !cache.licenseId || !install) return;
    const device = await licGet(LICENSE_DEVICE_KEY);
    const browser = await licGet(LICENSE_BROWSER_KEY);
    const body = { licenseId: cache.licenseId, installationId: install };
    if (device && /^[a-f0-9]{64}$/i.test(device)) body.deviceId = device;
    // Durable browser id, so this ~24h revalidation matches the same activation
    // the content script created (and survives a reinstall).
    if (browser && LICENSE_BROWSER_ID_RE.test(browser)) body.browserId = browser;
    const resp = await licenseFetch("/api/license/validate", body);
    const data = resp && resp.data;
    if (resp && resp.ok && data && data.success !== false && data.signedLicense) {
        licSet(LICENSE_CACHE_KEY, {
            token: data.signedLicense,
            licenseId: cache.licenseId,
            validationIntervalMs: data.validationIntervalMs || cache.validationIntervalMs || LICENSE_DEFAULT_INTERVAL_MS,
            graceMs: data.graceMs || cache.graceMs,
            lastValidatedAt: Date.now(),
            savedAt: Date.now(),
        });
        scheduleLicenseAlarm(data.validationIntervalMs || cache.validationIntervalMs);
    } else if (data && LICENSE_HARD_CODES.indexOf(data.code) !== -1) {
        licRemove(LICENSE_CACHE_KEY); // hard rejection (revoked/expired/…) → drop the cache
    }
    // Soft failure (offline / 5xx): leave the cache untouched — the grace window covers it.
}

function scheduleLicenseAlarm(intervalMs) {
    const minutes = Math.max(30, Math.round((intervalMs || LICENSE_DEFAULT_INTERVAL_MS) / 60000));
    try {
        chrome.alarms.create(LICENSE_ALARM, {
            periodInMinutes: minutes,
            delayInMinutes: Math.min(minutes, 60),
        });
    } catch (_) {}
}

chrome.runtime.onInstalled.addListener(() => scheduleLicenseAlarm());
if (chrome.runtime.onStartup) chrome.runtime.onStartup.addListener(() => scheduleLicenseAlarm());
if (chrome.alarms) {
    chrome.alarms.onAlarm.addListener((a) => { if (a && a.name === LICENSE_ALARM) revalidateLicense(); });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.action) return;
    if (msg.action === "license_fetch") {
        licenseFetch(String(msg.endpoint || ""), msg.body).then(sendResponse);
        return true; // keep the channel open for the async response
    }
    if (msg.action === "otp_fetch") {
        otpFetch(String(msg.endpoint || ""), msg.body).then(sendResponse);
        return true; // keep the channel open for the async response
    }
    if (msg.action === "captcha_fetch") {
        captchaFetch(String(msg.endpoint || ""), msg.body).then(sendResponse);
        return true; // keep the channel open for the async response
    }
    if (msg.action === "proxy_ip_fetch") {
        proxyIpFetch().then(sendResponse);
        return true; // keep the channel open for the async response
    }
    if (msg.action === "proxy_shift") {
        proxyShiftIp(msg.body).then(sendResponse);
        return true; // keep the channel open for the async response
    }
    if (msg.action === "license_schedule") {
        scheduleLicenseAlarm(msg.intervalMs);
        sendResponse && sendResponse({ ok: true });
        return true;
    }
});





