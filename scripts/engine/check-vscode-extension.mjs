#!/usr/bin/env node
// opentidehq/vscode-extension pins three assets of an engine release in its pins.json: the highlights
// zip, the browser build (opentide-wasm-web-<v>.zip) and THIRD-PARTY-LICENSES.html, each by URL and
// SHA-256. This runs the extension's own scripts on a release's assets, as they would run once
// pins.json names this repository's release:
//
//   node scripts/engine/check-vscode-extension.mjs <vscode-extension checkout> <assets dir> <tag>
//
// It writes pins.json in that checkout (the URLs of <tag>'s release here, the digests of SHA256SUMS),
// then runs the extension's own checks on the local files: `scripts/grammars.mjs --zip` (the grammars
// it bundles), `prepareEngine` from `scripts/engine-lib.mjs` (the engine it bundles) and
// `prepareWasi` from `scripts/wasi-lib.mjs` (the WASI command line, `opentide-wasm32-wasip1.wasm`, and
// its licence set: docs/internal/vscode-wasi.md), each served from the assets directory instead of
// the release's URLs, so each file is checked against the digest pins.json names. Any refusal fails.
// The licence set the extension requires (`WASI_LICENCES`) must be the one this script pins. It
// prints the pins.json sections the extension's pull request would carry. ci.yml runs it on the
// nightly, on the engine release dry run's assets (job engine-release-consumers), against the
// extension commit that job pins.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REPOSITORY = "opentidehq/opentide";
// The release train's tags (vX.Y.Z, vX.Y.Z-rc.N); the engine's own engine-v* series ended there.
const TAG = /^v(\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?)$/;
// The opentide command line on wasm32-wasip1: scripts/engine/release.py CLI_WASM_ASSET. The name is
// fixed, the extension pins it.
export const WASI_CLI = "opentide-wasm32-wasip1.wasm";
// The WASI module's licence set, release assets beside it (engine-release-build.yml's `licences`).
export const WASI_LICENCE_FILES = [
  "THIRD-PARTY-LICENSES.html",
  "WASI-LIBC-LICENSES.txt",
  "LICENSE",
  "NOTICE",
  "THIRD-PARTY-DATA-LICENSES.txt",
];

function fail(message) {
  console.error(`check-vscode-extension: ${message}`);
  process.exit(1);
}

/** SHA256SUMS as a map from asset name to digest, each digest checked against the file. */
function sums(dir) {
  const path = join(dir, "SHA256SUMS");
  if (!existsSync(path)) fail(`${path} is missing`);
  const digests = new Map();
  for (const line of readFileSync(path, "utf8").split("\n").filter(Boolean)) {
    const match = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line);
    if (!match) fail(`not a sha256sum line: ${line}`);
    const [, digest, name] = match;
    const actual = createHash("sha256").update(readFileSync(join(dir, name))).digest("hex");
    if (actual !== digest) fail(`${name}: the digest does not match SHA256SUMS`);
    digests.set(name, digest);
  }
  return digests;
}

/** The pins.json sections for `tag`'s release of this repository. */
export function pinsFor(tag, digests) {
  const match = TAG.exec(tag);
  if (!match) fail(`${tag} is not a release tag (vX.Y.Z or vX.Y.Z-rc.N)`);
  const version = match[1];
  const base = `https://github.com/${REPOSITORY}/releases/download/${tag}`;
  const pin = (name) => {
    const sha256 = digests.get(name);
    if (!sha256) fail(`SHA256SUMS has no ${name}`);
    return { url: `${base}/${name}`, sha256 };
  };
  return {
    highlights: { version, ...pin(`highlights-v${version}.zip`) },
    engine: {
      version,
      ...pin(`opentide-wasm-web-v${version}.zip`),
      thirdPartyLicenses: pin("THIRD-PARTY-LICENSES.html"),
    },
    // One module for every platform, named without a version: the release is the version.
    // The module's third-party licences, shipped beside it: the Rust crates (about.toml names
    // wasm32-wasip1), the C library it links, the licence, the embedded data's notice and the
    // licence files that notice cites. `licences`: the extension's key (its pins.json).
    wasi: {
      version,
      ...pin(WASI_CLI),
      licences: Object.fromEntries(WASI_LICENCE_FILES.map((name) => [name, pin(name)])),
    },
  };
}

async function main() {
  const [extArg, assetsArg, tag] = process.argv.slice(2);
  if (!extArg || !assetsArg || !tag) {
    fail("usage: check-vscode-extension.mjs <vscode-extension checkout> <assets dir> <tag>");
  }
  const ext = resolve(extArg);
  const assets = resolve(assetsArg);
  const pinsPath = join(ext, "pins.json");
  if (!existsSync(pinsPath)) fail(`${ext} has no pins.json`);
  const digests = sums(assets);
  const sections = pinsFor(tag, digests);

  const pins = JSON.parse(readFileSync(pinsPath, "utf8"));
  // The WASI module is a WebAssembly binary: \0asm, version 1.
  const wasi = readFileSync(join(assets, WASI_CLI));
  if (wasi.length < 8 || !wasi.subarray(0, 8).equals(Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]))) {
    fail(`${WASI_CLI} is not a WebAssembly module`);
  }
  for (const key of ["highlights", "engine", "wasi"]) {
    if (!pins[key]) fail(`pins.json has no ${key}: the extension's format changed`);
    // Keep the extension's own fields ($comment); replace what names the release.
    pins[key] = { ...pins[key], ...sections[key] };
  }
  writeFileSync(pinsPath, `${JSON.stringify(pins, null, 2)}\n`);

  // The grammars: the extension's script reads pins.json and checks the zip against its SHA-256.
  const highlights = join(assets, `highlights-v${sections.highlights.version}.zip`);
  const grammars = spawnSync(process.execPath, [join(ext, "scripts", "grammars.mjs"), "--zip", highlights], {
    cwd: ext,
    stdio: "inherit",
  });
  if (grammars.status !== 0) fail(`scripts/grammars.mjs refused ${highlights}`);

  // The engine: prepareEngine checks both files against pins.json and the zip's entries.
  const { prepareEngine, GLUE, WASM } = await import(pathToFileURL(join(ext, "scripts", "engine-lib.mjs")).href);
  const root = mkdtempSync(join(tmpdir(), "vscode-extension-engine-"));
  const dir = await prepareEngine(root, pins.engine, {
    zipPath: join(assets, `opentide-wasm-web-v${sections.engine.version}.zip`),
    licensesPath: join(assets, "THIRD-PARTY-LICENSES.html"),
  });
  for (const name of [GLUE, WASM, "THIRD-PARTY-LICENSES.html"]) {
    if (!existsSync(join(dir, name))) fail(`prepareEngine left no ${name}`);
  }

  // The WASI command line: the extension's own checks (the pin complete, the module and each licence
  // file against its digest, the module a WebAssembly binary), each URL served from the assets.
  const { prepareWasi, WASI_LICENCES } = await import(pathToFileURL(join(ext, "scripts", "wasi-lib.mjs")).href);
  const required = [...WASI_LICENCES].sort().join(", ");
  const pinned = [...WASI_LICENCE_FILES].sort().join(", ");
  if (required !== pinned) fail(`the extension's WASI licence set is ${required}; this script pins ${pinned}`);
  const base = `https://github.com/${REPOSITORY}/releases/download/${tag}/`;
  const local = async (url) => {
    if (!String(url).startsWith(base)) fail(`prepareWasi asked for ${url}, not an asset of ${tag}`);
    const file = join(assets, basename(new URL(url).pathname));
    if (!existsSync(file)) return new Response(null, { status: 404 });
    return new Response(readFileSync(file));
  };
  const prepared = await prepareWasi(mkdtempSync(join(tmpdir(), "vscode-extension-wasi-")), pins.wasi, {
    modulePath: "",
    licencesDir: "",
    fetchImpl: local,
  });
  if (prepared.licences.size !== WASI_LICENCES.length) fail("prepareWasi did not return every licence file");

  console.log(`vscode-extension accepts ${tag}'s assets. Its pins.json would read:`);
  console.log(JSON.stringify(sections, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => fail(error?.stack ?? String(error)));
}
