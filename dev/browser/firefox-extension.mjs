// Builds dist/firefox-extension from extension/. Firefox runs MV3 background
// code only as scripts, which Chrome rejects, so extension/ stays Chrome's.
import path from "node:path";
import { build } from "./package-extension.mjs";

const root = path.resolve(import.meta.dirname, "../..");
export const firefoxExtension = path.join(root, "dist/firefox-extension");

export function buildFirefoxExtension() {
  return build(firefoxExtension, { target: "firefox" });
}

if (import.meta.main) console.log(`wrote ${path.relative(root, buildFirefoxExtension())}`);
