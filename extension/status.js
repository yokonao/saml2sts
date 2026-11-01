// Renders ?state=choose|done|listed|error, with role= or error= alongside.
const params = new URLSearchParams(location.search);
const state = params.get("state") ?? "done";
const STATES = {
  choose: {
    mark: "⌨",
    title: "Choose a role in your terminal",
    text: "saml2sts is waiting for you to pick one. This page updates when the credentials are in.",
  },
  done: {
    mark: "✓",
    title: "Signed in",
    text: "The credentials are with saml2sts. Return to your terminal; you can close this tab.",
  },
  listed: {
    mark: "✓",
    title: "Got your roles",
    text: "saml2sts read the roles your IdP allows, without signing in to any. Return to your terminal; you can close this tab.",
  },
  error: { mark: "✕", title: "Sign-in failed", text: "" },
};
const s = STATES[state] ?? STATES.done;
document.body.dataset.state = state;
document.querySelector(".mark").textContent = s.mark;
document.querySelector("h1").textContent = s.title;
document.querySelector("p").textContent = state === "error" ? (params.get("error") ?? "") : s.text;

const role = params.get("role");
if (state === "done" && role) {
  const code = document.createElement("code");
  code.textContent = role;
  document.querySelector("h1").append(" as ", code);
}
document.title = `saml2sts: ${s.title}`;
