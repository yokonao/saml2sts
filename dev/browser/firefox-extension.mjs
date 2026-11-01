// Builds dist/firefox-extension from extension/. Firefox runs MV3 background
// code only as scripts, which Chrome rejects, so extension/ stays Chrome's.
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
export const firefoxExtension = path.join(root, "dist/firefox-extension");

export function buildFirefoxExtension() {
  rmSync(firefoxExtension, { recursive: true, force: true });
  cpSync(path.join(root, "extension"), firefoxExtension, { recursive: true });
  const file = path.join(firefoxExtension, "manifest.json");
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  manifest.background = { scripts: [manifest.background.service_worker] };
  // Only Chrome derives the extension ID from it.
  delete manifest.key;
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
  return firefoxExtension;
}

if (import.meta.main) console.log(`wrote ${path.relative(root, buildFirefoxExtension())}`);
