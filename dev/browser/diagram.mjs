// Renders each docs/<name>.html diagram to docs/images/<name>-{light,dark}.png.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Browser, computeExecutablePath, install } from "@puppeteer/browsers";
import puppeteer from "puppeteer-core";

const CHROME = "156.0.8078.80";
const DIAGRAMS = ["flow", "agent"];
const root = path.resolve(import.meta.dirname, "../..");
const cacheDir = path.join(import.meta.dirname, ".cache");

await install({ browser: Browser.CHROME, buildId: CHROME, cacheDir });
const browser = await puppeteer.launch({
  executablePath: computeExecutablePath({ browser: Browser.CHROME, buildId: CHROME, cacheDir }),
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 800, deviceScaleFactor: 2 });
  for (const name of DIAGRAMS) {
    for (const theme of ["light", "dark"]) {
      const url = pathToFileURL(path.join(root, "docs", `${name}.html`));
      url.searchParams.set("theme", theme);
      await page.goto(url.href);
      const out = path.join(root, "docs/images", `${name}-${theme}.png`);
      await (await page.$("#diagram svg")).screenshot({ path: out });
      console.log(`wrote ${path.relative(root, out)}`);
    }
  }
} finally {
  await browser.close();
}
