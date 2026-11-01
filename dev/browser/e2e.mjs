// Runs the whole flow in a real browser with the extension loaded: it signs in
// to Keycloak while `saml2sts login` waits. E2E_BROWSER=firefox runs the Firefox
// in /Applications instead of Chrome for Testing; HEADFUL=1 shows the window.
// Needs `docker compose up -d && ./setup.sh` in dev/ first.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { Browser, computeExecutablePath, install } from "@puppeteer/browsers";
import puppeteer from "puppeteer-core";
import { buildFirefoxExtension } from "./firefox-extension.mjs";

const CHROME = "156.0.8078.80";
// A Firefox downloaded into .cache cannot start its content processes on
// macOS 27, so the installed one is used.
const FIREFOX = process.env.FIREFOX ?? "/Applications/Firefox.app/Contents/MacOS/firefox";
const CHROME_EXTENSION_ID = "ljanpcedhfnidohflcgdjflhhjebpikb";
const FIREFOX_EXTENSION_ID = "saml2sts@yokonao.github.io";
const IDP_URL = "http://127.0.0.1:8080/realms/poc/protocol/saml/clients/aws";

const which = process.env.E2E_BROWSER ?? "chrome";
if (!["chrome", "firefox"].includes(which)) throw new Error("E2E_BROWSER must be chrome or firefox");
const firefox = which === "firefox";

const root = path.resolve(import.meta.dirname, "../..");
const bin = path.join(root, "bin/saml2sts");
const extension = path.join(root, "extension");
const cacheDir = path.join(import.meta.dirname, ".cache");
const work = mkdtempSync(path.join(tmpdir(), "saml2sts-"));
const userDataDir = path.join(work, "profile");
const env = {
  ...process.env,
  SAML2STS_CONFIG: path.join(work, "config.toml"),
  AWS_CONFIG_FILE: path.join(work, "aws-config"),
};

writeFileSync(
  env.SAML2STS_CONFIG,
  `[idp]
url = "${IDP_URL}"
duration = "1h"
sts_endpoint = "http://127.0.0.1:4566"

[roles]
poc-admin = "arn:aws:iam::000000000000:role/poc-admin"
poc-readonly = "arn:aws:iam::000000000000:role/poc-readonly"
`,
);

const run = (args, opts = {}) =>
  execFileSync(args[0], args.slice(1), { cwd: root, env, encoding: "utf8", ...opts });

// Firefox reads hosts only from the user-wide directory, so put back whatever
// was there.
const firefoxHost = path.join(homedir(), "Library/Application Support/Mozilla/NativeMessagingHosts",
  "io.github.yokonao.saml2sts.json");
const savedFirefoxHost = firefox && existsSync(firefoxHost) ? readFileSync(firefoxHost) : null;

function startLogin(args) {
  return start(["login", ...args]);
}

function start(args) {
  const proc = spawn(bin, [...args, "--no-open", "--timeout", "60s"], {
    cwd: root, env, stdio: ["pipe", "inherit", "inherit"],
  });
  const done = new Promise((resolve, reject) =>
    proc.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${args.join(" ")} exited ${code}`)))));
  return { proc, done };
}

// waitForTab waits until the tab shows the extension's status page with query.
async function waitForTab(page, query) {
  const want = new RegExp(`^(chrome|moz)-extension://[^/]+/status\\.html\\?${query}$`);
  for (let i = 0; !want.test(page.url()); i++) {
    if (i === 100) throw new Error(`tab is on ${page.url()}, not the status page with ${query}`);
    await new Promise((r) => setTimeout(r, 100));
  }
  console.log(`tab shows ${page.url()}`);
}

let browser;
try {
  run(["go", "build", "-o", bin, "./cmd/saml2sts"]);
  if (firefox) {
    run([bin, "install", "--browser", "firefox", "--extension-id", FIREFOX_EXTENSION_ID]);
  } else {
    run([bin, "install", "--extension-id", CHROME_EXTENSION_ID, "--user-data-dir", userDataDir]);
  }

  let executablePath = FIREFOX;
  if (!firefox) {
    await install({ browser: Browser.CHROME, buildId: CHROME, cacheDir });
    executablePath = computeExecutablePath({ browser: Browser.CHROME, buildId: CHROME, cacheDir });
  } else if (!existsSync(FIREFOX)) {
    throw new Error(`no Firefox at ${FIREFOX}; install it or set FIREFOX`);
  }
  browser = await puppeteer.launch({
    browser: which,
    executablePath,
    headless: !process.env.HEADFUL,
    // The host the browser starts inherits this, and with it the config path.
    env,
    ...(firefox ? {} : { userDataDir, pipe: true, enableExtensions: [extension] }),
  });
  if (firefox) await browser.installExtension(buildFirefoxExtension());

  const page = await browser.newPage();

  console.log(`--- profiles sync, reading the roles (${which})`);
  const sync = start(["profiles", "sync", "--refresh", "--path", bin,
    "--region", "us-east-1", "--endpoint-url", "http://127.0.0.1:4566"]);
  await page.goto(IDP_URL);
  await page.locator("#username").fill("alice");
  await page.locator("#password").fill("alice");
  await Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded" }).catch(() => {}),
    page.locator("#kc-login").click(),
  ]);
  await sync.done;
  await waitForTab(page, "state=listed");

  console.log("--- login --role poc-admin");
  // The IdP session from the first sign-in answers without the form.
  let login = startLogin(["--role", "poc-admin"]);
  await page.goto(IDP_URL);
  await login.done;
  await waitForTab(page, "state=done&role=poc-admin");

  console.log("--- login, choosing the role in the terminal");
  login = startLogin([]);
  await page.goto(IDP_URL);
  await waitForTab(page, "state=choose");
  login.proc.stdin.end("2\n");
  await login.done;
  await waitForTab(page, "state=done&role=poc-readonly");

  console.log("--- the AWS CLI through the profiles");
  for (const role of ["poc-admin", "poc-readonly"]) {
    console.log(run(["aws", "sts", "get-caller-identity", "--profile", `saml2sts-${role}`,
      "--query", "Arn", "--output", "text"]).trim());
  }

  console.log("--- GetCallerIdentity with exec, for each role");
  for (const role of ["poc-admin", "poc-readonly"]) {
    console.log(run([bin, "exec", "--role", role, "--timeout", "5s", "--", "sh", "-c",
      'curl -sf --aws-sigv4 aws:amz:us-east-1:sts --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" ' +
      '-H "x-amz-security-token: $AWS_SESSION_TOKEN" -d "Action=GetCallerIdentity&Version=2011-06-15" ' +
      "http://127.0.0.1:4566/"]).match(/<Arn>(.*)<\/Arn>/)[1]);
  }
} finally {
  await browser?.close();
  // Each build is a new binary to the Keychain access list, so drop what this one wrote.
  run([bin, "logout", "--all"], { stdio: "ignore" });
  if (firefox) {
    if (savedFirefoxHost) writeFileSync(firefoxHost, savedFirefoxHost);
    else rmSync(firefoxHost, { force: true });
  }
  rmSync(work, { recursive: true, force: true });
}
