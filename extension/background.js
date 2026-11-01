const HOST = "io.github.yokonao.saml2sts";

const BADGE = {
  ok: { text: "OK", color: "#1a7f37" },
  error: { text: "ERR", color: "#cf222e" },
};

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.method !== "POST") return;
    const samlResponse = details.requestBody?.formData?.SAMLResponse?.[0];
    if (!samlResponse) return;

    // A port rather than sendNativeMessage, since the host replies twice when
    // the user has to choose a role.
    const port = chrome.runtime.connectNative(HOST);
    let replied = false;
    port.onMessage.addListener((reply) => {
      replied = true;
      switch (reply.status) {
        case "idle": // No CLI is waiting: an ordinary console sign-in.
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
          showStatus(details.tabId, { state: "error", error: reply.error ?? "" });
      }
    });
    port.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError;
      if (err && !replied) {
        console.error("saml2sts:", err.message);
        showBadge("error");
      }
    });
    port.postMessage({ samlResponse });
  },
  {
    urls: [
      "https://signin.aws.amazon.com/saml",
      "https://*.signin.aws.amazon.com/saml",
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

function showBadge(kind) {
  const { text, color } = BADGE[kind];
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
  setTimeout(() => chrome.action.setBadgeText({ text: "" }), 10_000);
}
