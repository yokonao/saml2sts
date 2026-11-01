const HOST = "io.github.yokonao.saml2sts";

const BADGE = {
  ok: { text: "OK", color: "#1a7f37" },
  error: { text: "ERR", color: "#cf222e" },
};

// How long after saml2sts opened a tab its SAML POST is still forwarded; the
// CLI waits five minutes by default.
const LOGIN_TTL_MS = 15 * 60_000;

// The CLI opens the IdP with #saml2sts=<nonce>. Remember that tab, in session
// storage since the service worker may stop before the sign-in ends.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const nonce = new URLSearchParams(new URL(details.url).hash.slice(1)).get("saml2sts");
  if (!nonce) return;
  chrome.storage.session.set({ [tabKey(details.tabId)]: { nonce, expires: Date.now() + LOGIN_TTL_MS } });
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(tabKey(tabId)));

// takeLogin returns the nonce of the login the tab was opened for, once.
async function takeLogin(tabId) {
  const key = tabKey(tabId);
  const login = (await chrome.storage.session.get(key))[key];
  if (!login) return null;
  await chrome.storage.session.remove(key);
  return Date.now() < login.expires ? login.nonce : null;
}

function tabKey(tabId) {
  return `tab:${tabId}`;
}

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.method !== "POST") return;
    const samlResponse = details.requestBody?.formData?.SAMLResponse?.[0];
    if (!samlResponse) return;
    // Any other sign-in, or a page posting a SAML response of its own, is
    // never read further or sent to the host.
    const nonce = await takeLogin(details.tabId);
    if (!nonce) return;

    // A port rather than sendNativeMessage, since the host replies twice when
    // the user has to choose a role.
    const port = chrome.runtime.connectNative(HOST);
    let replied = false;
    port.onMessage.addListener((reply) => {
      replied = true;
      switch (reply.status) {
        case "idle": // The login is over or not this one.
          return;
        case "choose":
          showStatus(details.tabId, { state: "choose" });
          return;
        case "ok":
          showBadge("ok");
          showStatus(details.tabId, { state: "done", role: reply.role });
          return;
        case "listed":
          showBadge("ok");
          showStatus(details.tabId, { state: "listed" });
          return;
        default:
          console.error("saml2sts:", reply.error);
          showBadge("error");
          showError(details.tabId, reply.error ?? "");
      }
    });
    port.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError;
      if (err && !replied) {
        console.error("saml2sts:", err.message);
        showBadge("error");
      }
    });
    port.postMessage({ samlResponse, nonce });
  },
  {
    urls: [
      "https://signin.aws.amazon.com/saml",
      "https://*.signin.aws.amazon.com/saml",
      "https://signin.amazonaws-us-gov.com/saml",
      "https://*.signin.amazonaws-us-gov.com/saml",
      "https://signin.amazonaws.cn/saml",
      "https://*.signin.amazonaws.cn/saml",
    ],
    types: ["main_frame"],
  },
  ["requestBody"],
);

// showStatus replaces the AWS page, of no use for a sign-in meant for the CLI.
function showStatus(tabId, params) {
  const url = new URL(chrome.runtime.getURL("status.html"));
  for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
  chrome.tabs.update(tabId, { url: url.href });
}

// showError keeps the message out of the URL, and so out of the history.
async function showError(tabId, error) {
  const id = crypto.randomUUID();
  await chrome.storage.session.set({ [`error:${id}`]: error });
  showStatus(tabId, { state: "error", id });
}

function showBadge(kind) {
  const { text, color } = BADGE[kind];
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
  setTimeout(() => chrome.action.setBadgeText({ text: "" }), 10_000);
}
