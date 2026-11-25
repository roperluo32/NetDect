// Builds src-tauri/resources/providers.json from VPSDance/ai-proxy-rules data/providers/*.yaml.
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const REPO = "VPSDance/ai-proxy-rules";
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../src-tauri/resources/providers.json");
const headers = { "User-Agent": "NetDect-sync" };

async function getJson(url) {
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

async function getText(urls) {
  for (const url of urls) {
    for (let i = 0; i < 2; i++) {
      try {
        const r = await fetch(url, { headers });
        if (r.ok) return await r.text();
      } catch {}
    }
  }
  throw new Error(`download failed: ${urls[0]}`);
}

async function listFiles() {
  try {
    const tree = await getJson(`https://api.github.com/repos/${REPO}/git/trees/main?recursive=1`);
    return tree.tree.map((t) => `/${t.path}`);
  } catch (e) {
    console.warn(`GitHub API failed (${e.message}), falling back to jsDelivr listing`);
    const listing = await getJson(`https://data.jsdelivr.com/v1/packages/gh/${REPO}@main?structure=flat`);
    return listing.files.map((f) => f.name);
  }
}

const files = (await listFiles()).filter((n) => /^\/data\/providers\/[^/]+\.yaml$/.test(n));
console.log(`providers: ${files.length}`);

const providers = [];
const queue = [...files];
await Promise.all(
  Array.from({ length: 8 }, async () => {
    while (queue.length) {
      const f = queue.shift();
      const doc = parse(
        await getText([
          `https://cdn.jsdelivr.net/gh/${REPO}@main${f}`,
          `https://raw.githubusercontent.com/${REPO}/main${f}`,
        ]),
      );
      if (doc?.provider) {
        delete doc.allowDangerousDomainSuffix;
        doc.scope ??= "global";
        providers.push(doc);
      }
    }
  }),
);
providers.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));

await mkdir(dirname(out), { recursive: true });
await writeFile(
  out,
  JSON.stringify({ source: `https://github.com/${REPO}`, updated_at: Math.floor(Date.now() / 1000), providers }, null, 1),
);
console.log(`wrote ${providers.length} providers -> ${out}`);
