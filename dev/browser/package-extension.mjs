// Packages extension/ for an organization's own distribution:
//
//   node package-extension.mjs --host-name com.example.saml2sts \
//     [--key key.pem] [--gecko-id saml2sts@example.com] [--chrome /path/to/chrome]
//
// writes to dist/extension/:
//   chrome-web-store.zip  for the Chrome Web Store, which assigns the ID
//   chrome/               unpacked, with the key of --key pinning its ID
//   saml2sts.crx          signed with --key, for self-hosting; needs Chrome
//   firefox.zip           for addons.mozilla.org or `web-ext sign`
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";

const root = path.resolve(import.meta.dirname, "../..");
const hostName = /^[a-z0-9_]+(\.[a-z0-9_]+)*$/;

// build copies extension/ to out for "chrome" or "firefox", connecting to
// host and, for Chrome, carrying publicKey (base64 DER) or no key at all.
export function build(out, { target, host, publicKey, geckoID }) {
  rmSync(out, { recursive: true, force: true });
  cpSync(path.join(root, "extension"), out, { recursive: true });
  const file = path.join(out, "manifest.json");
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  delete manifest.key;
  if (target === "firefox") {
    // Firefox runs MV3 background code only as scripts, which Chrome rejects.
    manifest.background = { scripts: [manifest.background.service_worker] };
    if (geckoID) manifest.browser_specific_settings.gecko.id = geckoID;
  } else {
    delete manifest.browser_specific_settings;
    if (publicKey) manifest.key = publicKey;
  }
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
  if (host) {
    const bg = path.join(out, "background.js");
    const src = readFileSync(bg, "utf8");
    const replaced = src.replace(/^const HOST = ".*";$/m, `const HOST = ${JSON.stringify(host)};`);
    if (replaced === src && !src.includes(`const HOST = ${JSON.stringify(host)};`)) {
      throw new Error("background.js has no HOST constant to replace");
    }
    writeFileSync(bg, replaced);
  }
  return out;
}

// chromeID derives the extension ID Chrome gives a public key.
export function chromeID(publicKeyDER) {
  const hex = createHash("sha256").update(publicKeyDER).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function zip(dir, file) {
  rmSync(file, { force: true });
  execFileSync("zip", ["-qrX", file, "."], { cwd: dir });
}

function main() {
  const { values } = parseArgs({
    options: {
      "host-name": { type: "string" },
      key: { type: "string" },
      "gecko-id": { type: "string" },
      chrome: { type: "string" },
      out: { type: "string", default: path.join(root, "dist/extension") },
    },
  });
  const host = values["host-name"];
  if (!host || !hostName.test(host)) throw new Error("--host-name must be dot-separated parts of a-z, 0-9 and _");
  const out = path.resolve(values.out);
  mkdirSync(out, { recursive: true });

  zip(build(path.join(out, "chrome-web-store"), { target: "chrome", host }), path.join(out, "chrome-web-store.zip"));
  rmSync(path.join(out, "chrome-web-store"), { recursive: true });
  console.log(`wrote ${path.join(out, "chrome-web-store.zip")}; the Chrome Web Store assigns its ID`);

  if (values.key) {
    const der = createPublicKey(readFileSync(values.key)).export({ type: "spki", format: "der" });
    const chrome = build(path.join(out, "chrome"), { target: "chrome", host, publicKey: der.toString("base64") });
    console.log(`wrote ${chrome}/, extension ID ${chromeID(der)}`);
    if (values.chrome) {
      // Chrome takes only PKCS#8, which `openssl genrsa` does not write.
      const tmp = mkdtempSync(path.join(tmpdir(), "saml2sts-key-"));
      const pkcs8 = path.join(tmp, "key.pem");
      writeFileSync(pkcs8, createPrivateKey(readFileSync(values.key)).export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      try {
        // Chrome writes <dir>.crx next to the directory it packs.
        execFileSync(values.chrome, [`--pack-extension=${chrome}`, `--pack-extension-key=${pkcs8}`, "--no-message-box"]);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      if (!existsSync(`${chrome}.crx`)) throw new Error("Chrome did not write the CRX");
      renameSync(`${chrome}.crx`, path.join(out, "saml2sts.crx"));
      console.log(`wrote ${path.join(out, "saml2sts.crx")}`);
    } else {
      console.log("pass --chrome with a Chrome binary to also write a signed CRX");
    }
  }

  const firefox = build(path.join(out, "firefox"), { target: "firefox", host, geckoID: values["gecko-id"] });
  zip(firefox, path.join(out, "firefox.zip"));
  rmSync(firefox, { recursive: true });
  console.log(`wrote ${path.join(out, "firefox.zip")}; sign it on addons.mozilla.org or with web-ext sign`);
}

if (import.meta.main) main();
