---
title: Antivirus false positives, 2026-11-21
description: Investigation of the ClamAV and YARA detections on opentide's distributables, their causes by experiment, the Marketplace removal record of opentidehq.opentide, and the options to clear them.
---

# Antivirus false positives on opentide's distributables — investigation, 2026-11-21

Status: investigation only. Nothing was changed, published or uploaded; every scan ran locally.
Branch `investigate/av-false-positives`, no PR.

## 1. Summary

- **One signature is the only detection a local scanner raised on any released artifact:** ClamAV
  `Win.Coinminer.Generic-7150608-0`. It fires on the **Windows PE binaries only** (`opentide.exe`,
  `opentide-lsp.exe`, the `win_amd64` wheels' `_native.pyd`), never on the Linux ELF, WASM, VSIX, zip or sdist
  files that carry the same bytes.
- **Cause, confirmed by experiment:** the string `mine.moneropool.com`, which sits in three crypto-miner
  domain lists (`miner_domains`, `https_miner_domains`, `http_miner_domains`) of the Falco default-rules
  catalog, `data/catalogs/falco/defaults.toml`, compiled into every binary as plain text. The signature is
  `mine.moneropool.com` AND `miner` AND `pass` (case-insensitive) in a PE. Changing one character of the
  domain, or storing the catalog deflated, makes the hit disappear against all 3 628 232 signatures.
- **The vocabularies the owner suspected (ATT&CK, malapi) do not trigger ClamAV.** They do trigger
  public YARA rules (signature-base: `Mimikatz_Memory_Rule_1`, `HKTL_Keyword_InjectDLL`,
  `Hacktool_Strings_p0wnedShell`), through ATT&CK/datasource *descriptions* (`sekurlsa::logonPasswords`,
  `InjectDLL`, `Invoke-Mimikatz`). Those are hunting rules, not AV engines; they are the closest local proxy
  for the string heuristics commercial engines use. Elastic's `protections-artifacts` YARA set: 0 hits.
- **The Marketplace delisting is recorded publicly:** `microsoft/vsmarketplace` `RemovedPackages.md` lists
  `opentidehq.opentide | 11/8/2026 | Malware`. The first PyPI release that carries the miner domains in its
  Windows `.pyd` is 0.21.0 (2026-11-03); extension 0.1.0 and 0.1.1 (11-04, 11-05) bundled opentide 0.22.0 in
  their platform packages. That ordering fits, but **which engine flagged what is not observable** from
  outside, so it is an inference, not a proof.
- **Recommendation (section 8):** store the embedded datasets deflated or zstd-compressed (not XOR: that
  trips a different rule), defang or drop the miner domain items, keep the extension free of PE binaries,
  and file the false-positive reports and the Marketplace appeal in parallel. Compression also shrinks the
  Windows exe by about 9.8 MB.

- **RedLine (section 9):** 0 hits for every RedLine rule in Elastic, YARA-Forge (16), signature-base and the
  ReversingLabs infostealer set, and no stealer paths, wallet IDs or browser store names in the datasets beyond one
  ATT&CK `Login Data` path; compression removes all stealer strings, but the CLI's user32 key-translation imports
  and the Google ADC path strings remain.

### What this investigation could not do

- The `opentidehq/vscode-extension` PR #95 build (feat/agent-knowledge) **was not reproduced**: attaching
  that repository was refused by the session's permission layer, and I did not route around the refusal.
  Proxies used instead: the released `opentide-lsp-wasm32-wasip1.wasm` (the same module build the PR
  embeds) and the public `opentidehq/skills` repository at `fef6b57` (35 skill directories, 92 files; the PR
  embeds 34 of them).
- Microsoft Defender, the Marketplace's own scanners and VirusTotal engines are not available locally and
  were not used. Only ClamAV and YARA were run.
- No timing was taken inside Rust; decode costs below are Python and CLI measurements (indicative).

## 2. Method

| Item | Value |
|---|---|
| ClamAV | 1.5.4; `main.cvd` v63, `daily.cvd` v28190, `bytecode.cvd` v339 (3 628 232 signatures) fetched with `freshclam` on 2026-11-21 |
| YARA | 4.5.0 with [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) @ `78d979e` (754 rule files, externals defined) and [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) @ `418cfd9` (1057 files) |
| Scans | `clamscan -r --scan-archive=yes` on the raw artifacts, then on every extracted tree; `yara -C --scan-list` on every file |
| PE analysis | `pefile` (imports, sections, entropy, certificate directory) |
| Dataset matching | every tracked file under `data/`, `src/opentide/data/`, `highlights/`, `editors/`, `packages/` located by exact bytes (LF and CRLF) inside each binary |
| Constraint | nothing uploaded to any scanning service |

Release binaries match `SHA256SUMS` of the v1.0.0-rc.2 release.

## 3. Inventory

### 3.1 Artifacts scanned

| Artifact | Source | ClamAV | signature-base YARA | Elastic YARA |
|---|---|---|---|---|
| `opentide-v1.0.0-rc.2-x86_64-pc-windows-msvc.exe` (62.0 MB) | GitHub Release | **`Win.Coinminer.Generic-7150608-0`** | Mimikatz_Memory_Rule_1, HKTL_Keyword_InjectDLL | none |
| `opentide-lsp-v1.0.0-rc.2-x86_64-pc-windows-msvc.exe` (34.1 MB) | GitHub Release | **`Win.Coinminer.Generic-7150608-0`** | EXPL_Log4j_CVE_2021_44228_Dec21_Soft, Mimikatz_Memory_Rule_1, HKTL_Keyword_InjectDLL | none |
| `opentide-v1.0.0-rc.2-x86_64-unknown-linux-gnu` (51.8 MB) | GitHub Release | clean | Mimikatz_Memory_Rule_1, SUSP_Blocked_Download_Proxy_Replacement_Jan23_1 | none |
| `opentide-lsp-v1.0.0-rc.2-x86_64-unknown-linux-gnu` (29.4 MB) | GitHub Release | clean | Log4j, Mimikatz_Memory_Rule_1, SUSP_Blocked_Download | none |
| `opentide-lsp-wasm32-wasip1.wasm` (24.7 MB) | GitHub Release | clean | Log4j, Mimikatz_Memory_Rule_1, SUSP_Blocked_Download | none |
| `opentide-wasm-web-v1.0.0-rc.2.zip` (5.5 MB; wasm 23.5 MB) | GitHub Release | clean | same three as the wasm | none |
| `highlights-v1.0.0-rc.2.zip` | GitHub Release | clean | none | none |
| `opentide-1.0.0rc2` `win_amd64` wheel (23.2 MB; `_native.pyd` 67.6 MB) | PyPI | **`Win.Coinminer.Generic-7150608-0`** | Mimikatz_Memory_Rule_1, HKTL_Keyword_InjectDLL | none |
| `opentide-1.0.0rc2` `manylinux_2_28_x86_64` wheel (`_native.abi3.so` 56.6 MB) | PyPI | clean | Mimikatz_Memory_Rule_1, SUSP_Blocked_Download | none |
| `opentide-1.0.0rc2.tar.gz` (sdist, 30 MB unpacked) | PyPI | clean | none | none |
| `opentide-0.28.1` `win_amd64` wheel (`_native.pyd` 24.7 MB + 35 loose `.vocab.toml`) | PyPI | **`Win.Coinminer.Generic-7150608-0`** | Log4j, Mimikatz_Memory_Rule_1, HKTL_Keyword_InjectDLL; loose vocab files: Mimikatz_Memory_Rule_1, Hacktool_Strings_p0wnedShell, SUSP_Blocked_Download | none |
| `opentide-0.28.1` `manylinux_2_28_x86_64` wheel | PyPI | clean | Log4j, Mimikatz_Memory_Rule_1, SUSP_Blocked_Download | none |
| `opentidehq.opentide` 0.1.2 `.vsix` (4.33 MB; engine wasm 16.3 MB) | Open VSX | clean | Mimikatz_Memory_Rule_1, Hacktool_Strings_p0wnedShell (wasm; `readme.md`: `lsadump::dcsync`), SUSP_Blocked_Download (wasm, `changelog.md`) | none |
| `opentidehq.opentide` 0.1.1 `.vsix` (4.34 MB) | Open VSX | clean | same as 0.1.2 | none |
| `opentidehq/skills` @ `fef6b57` (proxy for the 34 embedded skills) | GitHub | clean | Hacktool_Strings_p0wnedShell (2 files: `Invoke-Mimikatz` in a detection query), SUSP_Blocked_Download (4 files, prose "blocked by") | none |

Historic `win_amd64` wheels (ClamAV with the coinminer signature only): 0.19.0 and 0.20.0 clean;
**0.21.0, 0.22.0, 0.23.0, 0.24.0, 0.24.1, 0.25.0 all `FOUND`** (the `.pyd` contains the three
`mine.moneropool.com` lines from 0.21.0 on).

### 3.2 Embedded datasets

All of the following are `include_str!`-compiled as **plain UTF-8 text** (TOML or JSON) and parsed on first
use. `OPENTIDE_ASSETS` points the build scripts at the workspace root
(`crates/opentide-*/build.rs`). Exact-byte matching found 337 of 408 candidate files embedded;
11.4 MB of unique files. Vocabularies and `pins`, `sentinel` are in every binary including the
VS Code engine wasm; per-language catalogs are in every binary; `diagnostics` and `setup` templates only in
the CLI and the `.pyd`.

| Dataset (path) | Files | Bytes embedded | Source | Licence | Carried by |
|---|---:|---:|---|---|---|
| `src/opentide/data/vocabulary/att&ck.vocab.toml` | 1 | 1 451 166 | MITRE ATT&CK STIX (v20.0) via `cargo xtask vocab ingest` | ATT&CK Terms of Use | all binaries, VSIX wasm (older revision) |
| `.../actors.vocab.toml` | 1 | 919 011 | ATT&CK + MISP galaxy (threat actors) | ATT&CK ToU; MISP galaxy per upstream (not checked) | all binaries |
| `.../att&ck.groups`, `mitigations`, `datasources` | 3 | 155 835 / 128 776 / 114 457 | ATT&CK | ATT&CK ToU | all binaries |
| `.../malapi.vocab.toml` | 1 | 129 470 | [malapi.io](https://malapi.io): 368 Windows API names with a description | upstream site; see licence note below | all binaries |
| `.../surface`, `collection`, `sectors`, `rsit`, others (34 files total) | 28 | ≈ 0.26 MB | authored / STIX / MISP / ENISA RSIT | per file | all binaries |
| `data/catalogs/falco/defaults.toml` (+ `fields`, `events`) | 3 | 479 766 | falcosecurity/rules (default and sandbox rules), libs, plugins | Apache-2.0 | all binaries |
| `data/catalogs/exabeam/{fields,values}.toml` | 2 | 291 922 | ExabeamLabs/CIMLibrary | Apache-2.0 | all binaries |
| `data/catalogs/kql/**` (12 files) | 12 | 4 529 481 | Microsoft Learn articles, ASIM, Sentinel/Defender schemas (see each file's header) | not checked per file | all binaries |
| `data/catalogs/{spl,esql,eql,cql,yaral,yara,ecs,carbon_black,bitdefender,tz}` | ≈ 24 | ≈ 1.9 MB | vendor docs, YARA-X, ECS | Apache-2.0, MIT, BSD-3, CC-BY-4.0, public domain (tz) | all binaries |
| `data/catalogs/tide/generated/fields.json` | 1 | 1 133 497 | generated by `cargo xtask codegen` | repo licence | all binaries |
| `src/opentide/data/{diagnostics,setup,configurations,pins,sentinel}` | 262 | ≈ 0.27 MB | authored; `sentinel/attack-v18.json` from ATT&CK | repo licence / ATT&CK ToU | CLI, `.pyd` (diagnostics, setup) |
| `highlights/spec.toml` | 1 | 3 567 | authored | repo licence | all binaries |

Licence note: the vocabulary directory has no `NOTICE` or `LICENSE` file, and `malapi.vocab.toml` names
only its `reference` URL (https://malapi.io); the licence of the data is worth checking independently of
the AV question.

Notes found on the way:

- **Windows binaries embed the catalogs with CRLF line endings** (the vocabularies keep LF): `.gitattributes`
  has `-text` rules for fixtures and templates but none for `data/catalogs/**`. The same source therefore
  yields different bytes per OS. Not an AV cause, but it makes the Windows binary's `.rdata` differ from
  Linux and breaks byte-for-byte reproducibility checks.
- **0.28.1 shipped the vocabularies twice**: as loose `.vocab.toml` files in the wheel and inside the
  `.pyd`. rc2 ships them only in the `.pyd`.
- **Extension 0.1.2 contains no skills, no templates and no PE**; its content is the JS bundles, the engine
  wasm (16.3 MB), TextMate grammars, `readme.md`, `changelog.md`, notices. Earlier platform packages
  (0.1.0, 0.1.1; see section 6) bundled CPython 3.13 and opentide 0.22.0.

## 4. Detections

### 4.1 ClamAV — `Win.Coinminer.Generic-7150608-0`

Definition from `daily.ldb` (`sigtool --find-sigs`):

```
Win.Coinminer.Generic-7150608-0;Engine:81-255,Target:1;0&1&2;
  6d696e652e6d6f6e65726f706f6f6c2e636f6d::i   -> "mine.moneropool.com"
  6d696e6572::i                               -> "miner"
  70617373::i                                 -> "pass"
```

`Target:1` is PE, which is why the same bytes in ELF, WASM and zip files do not alert. The only
distinctive string is the domain. `miner` and `pass` match almost any large text binary.

Where it hits (file offsets in the Windows CLI): `0x299bf2e`, `0x299c32b`, `0x299c51a`, the three lists
`miner_domains`, `https_miner_domains`, `http_miner_domains` in `data/catalogs/falco/defaults.toml`
(origin `falcosecurity/rules/rules/falco-sandbox_rules.yaml`). The matching string appears in all binaries
(Linux, wasm, `.pyd`), and in no other file of this repository outside two test fixtures
(`crates/testdata/conformance/external/lucene-carbon-black/net_connection_win_domain_crypto_mining_pools*.lucene`),
which no artifact carries.

### 4.2 YARA (signature-base)

These are community hunting rules (scores 50–70), not AV signatures; shown because commercial engines use
the same class of string heuristics.

| Rule | Condition | Matched string | Dataset | Artifacts |
|---|---|---|---|---|
| `Mimikatz_Memory_Rule_1` | 1 of `sekurlsa::*` and none of its `fp` strings (`"x_mitre_version": `, `"url":"https://attack.mitre.org/`, ...) | `sekurlsa::logonPasswords` | `att&ck.vocab.toml` (ATT&CK software description) | every binary incl. wasm, `.pyd`, `.so`, 0.28.1 loose file |
| `HKTL_Keyword_InjectDLL` | MZ header, `InjectDLL` and `Kernel32.dll` | `InjectDLL` (once) + `Kernel32.dll` (139×, real import names and malapi `Library :` lines) | `att&ck.vocab.toml` | Windows PEs and Windows `.pyd` only |
| `Hacktool_Strings_p0wnedShell` | 1 of its `$x*` and no `fp` | `Invoke-Mimikatz`, `lsadump::dcsync` | `datasources.vocab.toml`; extension `readme.md`; two skills | VSIX wasm and `readme.md`, 0.28.1 loose file |
| `EXPL_Log4j_CVE_2021_44228_Dec21_Soft` | `${jndi:ldap:/` and no `<html` | `${jndi:ldap:/` | `data/catalogs/exabeam/fields.toml` (field-description example) | LSP exe, Linux LSP, both wasm; not the CLI builds (not investigated why) |
| `SUSP_Blocked_Download_Proxy_Replacement_Jan23_1` | several generic phrases | `is blocked`, `blocked by` | ordinary prose in descriptions, `changelog.md`, skills | most files; pure noise |

`Mimikatz_Memory_Rule_1` already excludes the STIX JSON form of ATT&CK; opentide's TOML form is not
covered by those exclusions.

### 4.3 Heuristic triggers AV vendors commonly use

Case-insensitive counts per binary (identical across Windows, Linux and wasm builds, because they come from
the shared datasets):

| Trigger | Count in each binary | Origin |
|---|---:|---|
| Injection API names (`VirtualAllocEx` 10, `WriteProcessMemory` 12, `CreateRemoteThread` 9, `SetThreadContext` 10, `OpenProcess` 11, ...) | ≈ 120 | `malapi.vocab.toml` (names and descriptions) |
| Credential-theft words (`lsass` 35–42, `mimikatz` 27–29, `sekurlsa` 2, `lsadump` 3, `procdump` 2, `comsvcs.dll` 2, `Invoke-Mimikatz` 1) | 73–82 | ATT&CK vocab, datasources, Exabeam values, tests in CLI builds |
| C2 words (`beacon` 23, `empire` 12, `metasploit` 7, `cobaltstrike` 2, `meterpreter` 2, ...) | 50 | ATT&CK software descriptions |
| Miner words (`minexmr` 15, `nanopool` 14, `xmrig` 9, `moneropool` 3, `stratum+tcp` 1, `coinhive` 1, ...) | 44 | Falco catalog, ATT&CK software descriptions |
| Encoded-PowerShell words (`IEX(`, `DownloadString`, `Invoke-Expression`) | 2–3 | ATT&CK descriptions |
| AMSI bypass strings, EICAR | 0 | — |

PE structure (all four Windows PEs): **unsigned** (Authenticode directory size 0); no packing (`.text`
entropy 6.2, `.rdata` 6.0, only `.pdata` ≈ 7.1 as usual for x64 unwind data); the injection API names are
**not imports**: the real imports are ordinary Rust-std ones (`CreateProcessW`, `OpenProcessToken`,
`VirtualProtect`, `LoadLibraryA`, `GetProcAddress`, `TerminateProcess`; 221 imports from 18 DLLs for the CLI,
129 from 13 for the LSP). No known-bad hashes or live domains were found other than the Falco miner-domain lists.

## 5. Causality experiments

Method: locate each embedded dataset in the Windows binary by exact bytes (337 regions in the CLI and the
`.pyd`, 97 in the LSP), patch a copy in place, rescan. PE layout is preserved (compressed bytes zero-padded)
so the engines still treat the file as a PE.

ClamAV, full database (3 628 232 signatures) on the final variants; the coinminer signature alone on the
intermediate ones:

| Variant | CLI exe | LSP exe | `_native.pyd` |
|---|---|---|---|
| V0 original | **FOUND** | **FOUND** | **FOUND** |
| V1 one character of `mine.moneropool.com` changed (`...poo1...`) | clean | clean | clean |
| V2 only `falco/defaults.toml` deflated | clean | — | — |
| V3 only `att&ck.vocab.toml` deflated | **FOUND** | — | — |
| V5 all vocabularies deflated, catalogs left | **FOUND** | — | — |
| V6 all catalogs deflated, vocabularies left | clean | — | — |
| V4 all 337 datasets deflated | clean | clean | clean |
| V7 all datasets XORed with 0x5A | clean | clean | clean |

So: the coinminer hit is the Falco catalog and nothing else; the ATT&CK/malapi vocabularies are irrelevant
to ClamAV.

signature-base YARA, rules hit per variant (CLI exe):

| Variant | Rules |
|---|---|
| V0 original | HKTL_Keyword_InjectDLL, Mimikatz_Memory_Rule_1 |
| V1 domain defanged | same two |
| V2 Falco catalog deflated | same two |
| V3 ATT&CK vocab deflated | **none** |
| V5 vocabularies deflated | none |
| V6 catalogs deflated | same two |
| V4 all deflated | none (LSP: Log4j also gone; `.pyd` none) |
| **V7 all XORed 0x5A** | **`SUSP_XORed_Mozilla_Oct19` (new)** |

Two further results:

- **Obfuscation is itself detected.** XOR-encoding the datasets replaces the two content hits with a rule
  that looks for single-byte-XORed `Mozilla/5.0` (matched at `0x28b4ff6`): a user-agent string inside the
  datasets, XORed. This is the evidence for the risk noted in option (a): use a real compression format,
  not a byte XOR.
- **Option (b), measured.** Removing the `description` fields of the five MITRE vocabularies (2 769 245 →
  458 425 bytes) and emptying the three miner lists in the Falco catalog (about 2 KB of list items removed): ClamAV clean,
  signature-base YARA none, Elastic none. The identifier-only heuristics remain (`VirtualAllocEx` 6, `CreateRemoteThread` 6, `lsass` 21,
  `mimikatz` 2 in the stripped exe; the names themselves stay).

Other measurements:

| Quantity | Value |
|---|---|
| Unique embedded datasets (raw) | 11.43 MB |
| Per-file deflate-9 | 1.87 MB (16.4%), decode of all 32 ms |
| zstd -3 solid | 1.65 MB (14.4%), 19.9 ms incl. process start |
| zstd -19 solid | 1.25 MB (10.9%), 17.8 ms incl. process start |
| xz -9e solid | 1.19 MB (10.4%), 84 ms |
| Windows CLI `.rdata` | 20.5 MB → 10.7 MB; entropy 6.04 → 6.55 (still below the usual 7.0 "packed" threshold); individual blobs 8.0 |
| Baseline, Linux CLI | `--version` 4 ms; `validate` on `tests/fixtures/tide_corpus/current` 7–10 ms |
| Python `tomllib` parse | `att&ck` 140 ms, `actors` 97 ms, `malapi` 15 ms (parsing, not decoding, dominates; decode of the 1.45 MB ATT&CK file ≈ 6 ms) |

Decode of the whole set would be paid only if every dataset were touched; vocabularies and catalogs are
already loaded lazily (`OnceLock`), so a command pays for the datasets it reads.

## 6. The Marketplace delisting

Public signals only; no Marketplace account, tenant or private endpoint was contacted.

| Signal | Finding |
|---|---|
| `POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery` (criteria `filterType 7`, value `opentidehq.opentide`) | HTTP 200, `extensions: []`, `TotalCount: 0` |
| [`microsoft/vsmarketplace` `RemovedPackages.md`](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) | line 83: **`opentidehq.opentide | 11/8/2026 | Malware`**. 799 of the list's entries are `Malware`, 1236 `Impersonation`, 355 `Untrustworthy`, 146 `Spam`; no reason text beyond the type is given |
| [VS Code client block list `main.vscode-cdn.net/extensions/marketplace.json`](https://main.vscode-cdn.net/extensions/marketplace.json) | `opentidehq.opentide` is not in the `malicious` array (283 IDs), so installed copies are not force-uninstalled by that list |
| Open VSX `opentidehq/opentide` | 0.1.2 (2026-11-10T12:46Z) and 0.1.1 (2026-11-10T11:35Z) both live, publisher verified, 865 downloads, no scan or malicious flag in the API |

Policy sources:

- [Extension runtime security → Marketplace protections](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security):
  "The Marketplace runs a malware scan on each extension package ... which uses several antivirus engines ...
  run for each new extension and for each extension update"; dynamic detection in a sandboxed clean-room VM;
  unusual-usage monitoring; and "If a malicious extension is reported and verified ... the extension is
  removed from the Marketplace and added to a block list". RemovedPackages.md adds: "Every package ... is
  scanned upfront and regularly rescanned ... Scanning is not perfect."
- [Publishing extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension):
  "Once an extension is removed, its extension name is permanently reserved and cannot be reused, even by the
  original publisher." The page does not say whether that applies to a security removal.
- Contact route in the same page: sign in at *Manage Publishers & Extensions* and use **Contact Microsoft**
  (top right) for account or publishing support. Reports about someone else's extension go through *Report
  a concern* on the extension page, with a first response promised within one business day. No public appeal
  procedure for a "Malware" removal is documented; the
  [vsmarketplace issue tracker](https://github.com/microsoft/vsmarketplace/issues/new/choose) is the
  public feedback channel.
- Open VSX has [extension scanning](https://github.com/eclipse/openvsx/wiki/Extension-Scanning) with three
  checks only: secret detection, a SHA-256 blocklist of known-bad files, and namespace similarity; each can
  be monitor-only. There is no antivirus or string heuristic, and the operator is the contact for a blocklist
  mistake. Nothing flags opentide there.

Timeline (UTC dates):

| Date | Event |
|---|---|
| 2026-11-03 | opentide 0.21.0 on PyPI: first Windows `.pyd` with the Falco catalog (`Win.Coinminer.Generic-7150608-0` hits from here) |
| 2026-11-04 | extension 0.1.0 (platform packages bundling opentide 0.22.0 and CPython 3.13) |
| 2026-11-05 | extension 0.1.1 (same bundling; "seven platform packages") |
| **2026-11-08** | **`opentidehq.opentide` removed, type Malware** |
| 2026-11-10 | extension 0.1.2 (universal 4 MB package, no bundled runtime, no PE) on Open VSX; 0.1.1 also uploaded there |

Reading: the Marketplace served `win32-x64` packages carrying a PE (`_native.pyd` of 0.22.0) on which ClamAV's
Win.Coinminer signature fires, three days before the removal. That is consistent with an engine-driven
"Malware" decision, but ClamAV is only one of "several engines", Microsoft names none, and I cannot see
which sample, version or engine caused it. The 0.1.2 universal package, which has no PE, is
clean in ClamAV and Elastic, with only the signature-base noise listed above.

## 7. Options

Evidence column: result on this investigation's data. "Offline" is the effect on the zero-install, offline
design.

| Option | Clears the detections found? | Cost | Offline / zero-install |
|---|---|---|---|
| **(a) Compress datasets** (deflate or zstd, decoded at first use) | ClamAV: yes (V4, full DB). signature-base: yes (V4). Strings never appear in the file. XOR instead: ClamAV yes, but a new rule fires (`SUSP_XORed_Mozilla_Oct19`) | Build step in `include_str!` users (`opentide-schema`, `-falco`, `-exabeam`, `-cql`, ...) plus a decode layer; binaries get smaller (-9.8 MB `.rdata` in the Windows exe; 11.4 → 1.9 MB of data); decode ≤ 32 ms for everything, a few ms per dataset. `.rdata` entropy 6.5; blobs 8.0. Memory scanners and the Marketplace clean-room VM would still see strings after decode in memory (not testable here) | none: data stays inside the binary |
| **(b) Strip to identifiers** | ClamAV: yes. YARA: yes (V8). Heuristic API/tool names stay (malapi names, `lsass`) | Loses descriptions (hover and completion docs for ATT&CK, datasources, mitigations: 2.77 MB → 0.46 MB) and the Falco miner list items; changes what `opentide` can show | none |
| **(c) Separate signed data file, fetched or verified on first use** | Yes, as the PE and wasm no longer carry the text | Signing key and distribution, cache in `globalStorage`, version pinning, network access on first use | breaks zero-install and offline first run unless the file ships in a package (which is again a scannable file); not recommended |
| **(d) Remove or defang sample payloads in skills, templates, snippets** | The skills hit only generic YARA rules (two `Invoke-Mimikatz` detection queries) and ClamAV is clean; little to gain. The extension `readme.md` carries `lsadump::dcsync` | Reword two skills and one readme line | none |
| **(e) Sign and report** | Signing does not remove content signatures (the coinminer signature is body-based) but helps reputation heuristics (SmartScreen, Smart App Control). Reports: ClamAV removes a signature once confirmed; Microsoft clears a Defender detection | Authenticode via Azure Artifact Signing needs a paid Azure subscription and eligibility (organisation in the US, Canada, EU, UK and others; individuals in US or Canada); VSIX is signed by the Marketplace itself on publish, Open VSX offers a `.sigzip` (present on 0.1.2) | none |
| **(f) Defang just the miner domains at the source** | Yes (V1). Smallest possible change: keep the list names, drop or split the three `items` arrays that contain `mine.moneropool.com` | One build-time transform or a catalog sync change in `scripts/engine/sync_falco_catalog.py`; analysis of lists in Falco rules loses those items | none |
| **(g) Keep PEs out of the extension** | The 0.1.2 universal package has none; keep it that way | none (already done) | none |
| **(h) Gate releases with ClamAV and YARA** | Detects regressions before publish | CI job: `freshclam`, `clamscan`, `yara` with signature-base on `dist/` | none |

### Submission routes (e)

- **Microsoft Defender (WDSI):** file submission portal, [microsoft.com/wdsi/filesubmission](https://www.microsoft.com/wdsi/filesubmission),
  short link `aka.ms/wdsi`; guidance in
  [Address false positives/negatives in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives).
  Include: the exact file and its SHA-256, the product and download URL, the statement that the file is a
  static-analysis tool embedding publicly documented detection content, and the string and dataset found
  here. Community reports describe turnaround of a week or more; I did not submit anything.
- **ClamAV:** the false-positive form [clamav.net/reports/fp](https://www.clamav.net/reports/fp) or the
  `clamsubmit` tool (its man page lists the false-positive options). Include: signature name
  `Win.Coinminer.Generic-7150608-0`, the file, SHA-256, and the sentence "the match is the domain list of the
  Falco `miner_domains` list, used for detection". ClamAV's documentation says submissions are not shared outside
  Cisco, and that a change takes at least 48 hours to reach the databases. (These two pages return 403 from
  this environment's egress; the URLs come from ClamAV's published FAQ via search.)
- **Marketplace:** *Manage Publishers & Extensions* → **Contact Microsoft**, asking for review of
  `opentidehq.opentide` (removed 11/8/2026, "Malware") with the evidence from sections 4 and 5; fall back to a
  [vsmarketplace issue](https://github.com/microsoft/vsmarketplace/issues/new/choose). Ask explicitly whether
  the ID can be restored, since a removed name is documented as reserved.
- **Do not** upload the binaries to VirusTotal or similar to "check" them: that publishes the files and
  distributes them to vendors.

## 8. Recommendation

1. **Fix the cause now (smallest change first):** defang the miner-domain items of the Falco catalog at the
   source (option f). That alone clears the only ClamAV detection; it was verified on the CLI exe, LSP exe and
   `.pyd`.
2. **Then store every embedded dataset compressed** (option a, deflate or zstd, never XOR). It removes the
   entire class of text heuristics from every platform (ClamAV and signature-base both clean), shrinks the
   Windows exe from 62.0 MB by about 9.8 MB, and costs about 20–30 ms in total, spread over the datasets a
   command actually reads. Keep the lazy `OnceLock` loading so the decode is paid on use. Fold the same
   build step into `.gitattributes` (`data/catalogs/** -text`) so the compressed bytes are identical across
   OSes.
3. **Hold (b) in reserve:** stripping descriptions works, but costs user-visible documentation; only do it if
   a vendor still flags the compressed build.
4. **Keep the extension free of PE binaries** (already true of 0.1.2; the WASM engine is clean in ClamAV
   and Elastic) and re-run this investigation on the PR #95 build, whose WASI module and 34 skills I could not
   build here.
5. **In parallel:** file the ClamAV and WDSI false-positive reports for the already released rc.1 and rc.2
   Windows binaries and the 0.21–0.28 wheels, and open the Marketplace appeal for `opentidehq.opentide`,
   asking for the ID back. Plan for the ID not being restorable: publish the new build under a new ID only
   after the appeal is answered.
6. **Add a release gate** (option h) that runs ClamAV and signature-base YARA over every file in the
   release, so that a new dataset cannot reintroduce a hit unnoticed; consider Authenticode signing
   (option e) for the Windows binaries as a separate reputation measure.

## 9. RedLine (addendum, same day)

Request: Microsoft Defender is reported to flag opentide with RedLine Stealer signatures. Defender cannot
run here, so this section uses local proxies and the same rules as before (read-only, nothing uploaded).
Added rule sets: YARA-Forge `full` 2026 package (11 852 rules, public release asset, downloaded only),
ReversingLabs public rules (`yara/infostealer`, 8 files) and the Elastic and signature-base sets from section 2.
Scan targets: every Windows PE (both `.exe`, rc2 and 0.28.1 and 0.21.0 to 0.25.0 `_native.pyd`), the Linux
ELFs, the wasm modules, and the datasets as standalone files (`data/catalogs`, `src/opentide/data`,
`highlights`, the skills repo, the sdist tree): 1 760 files.

### 9.1 RedLine-specific rules: 0 hits

| Set | RedLine rules run | Hits |
|---|---|---:|
| Elastic `Windows_Trojan_RedLineStealer.yar` | `..._17ee6a17`, `_f54632eb`, `_3d9371fd`, `_63e7e006`, `_f07b3cb4`, `_4df4bcb6`, `_15ee6903`, `_6dfafd7b`, `_983cd7a7` | **0** each |
| YARA-Forge full | `ESET_Cw_Windows_Redline_Panel_{Tab_Headers,Distinctive_Strings,Prompts,Status_Message_Strings,Commands}`, `TRELLIX_ARC_Redline_Payload`, `ARKBIRD_SOLG_Mal_Stealer_NET_Redline_Aug_2020_1`, `SECUINFRA_MAL_Redline_Certificate_{Bosch,Geforce}`, `EMBEERESEARCH_Win_Redline_{Updated_Bytecodes_Oct_2023,Loader_Dec_2023,Bytecodes_Jan_2024,Payload_Dec_2023}`, `DITEKSHEN_MALWARE_Win_Redlinedropper{ahk,exe}`, `SEKOIA_Infostealer_Win_Redline_Strings` (16) | **0** each |
| signature-base | `SUSP_MAL_EXFIL_Stealer_Output_Characteristics_Sep22_1` (the only RedLine/Raccoon rule) | **0** |
| ReversingLabs public rules | no RedLine rule exists in the public set; its `infostealer` rules (Gomorrah, Lumar, StealC, Daolpu, Skuld, WeaselStore, two POS families) were run instead | **0** |
| Any stealer-family rule in any set | | the only family-named hit is `DITEKSHEN_MALWARE_Win_Asyncrat` (22 files), triggered by the bare word `AsyncRAT` in the ATT&CK/actors text, not by AsyncRAT code |

Other Forge rules that fire (none stealer-specific): `SIGNATURE_BASE_Mimikatz_Memory_Rule_1`,
`SIGNATURE_BASE_HKTL_Keyword_Injectdll`, `SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell`,
`SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_Dec21_Soft` (section 4.2), `GODMODERULES_IDDQD_God_Mode_Rule` (a
meta-rule of generic strings such as `sekurlsa::logonpasswords`, score 60), `DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Nonewindowsua`
(Windows PE containing iPhone/Android/Mac user-agent strings, score 40, 12 PEs) and `CAPE_Eternalromance` (one
PE, matched string `Frag`). After the compression experiment all of them are gone (9.3).

### 9.2 Stealer-target strings in the datasets and binaries

Census with word-boundary regexes (exact case for ambiguous words), per embedded dataset, then per binary.
A first, substring-based pass over-counted (`tdata` sits inside "metadata"; `Exodus` is a citation title;
`Phantom` is a SOAR product), so only the refined counts are reported.

| Target class | Strings searched | Found in datasets | Where |
|---|---|---|---|
| Stealer family names | `RedLine`, `Lumma`, `Vidar`, `StealC`, `Raccoon`, `stealer` | RedLine 2, Lumma 6, Vidar 2, StealC 1, "stealer" 61 (+1 in `fields.json`); Raccoon 0 | `actors.vocab.toml` (MISP descriptions: "...Atlantida Stealer, Rhadamanthys, RisePro, Lumma Stealer, and RedLine."), `att&ck.vocab.toml` (Lumma 2) |
| Browser credential stores | `Login Data`, `Local State`, `Web Data`, `logins.json`, `key4.db`, `cookies.sqlite`, `CryptUnprotectData`, `os_crypt`, `encrypted_key` | `Login Data` 1, `CryptUnprotectData` 2; the rest 0; the word `Cookies` 14 (ATT&CK, Sentinel schema, KQL tables) | `att&ck.vocab.toml` T1555.003 text: `AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data` and the `CryptUnprotectData` explanation |
| Crypto wallets | Electrum, Exodus (wallet), Atomic Wallet, MetaMask, Coinomi, Jaxx, Armory, `wallet.dat`, eight wallet-extension IDs incl. `nkbihfbeogaeaoehlefnkodbefgpgknn` | **0** | no wallet name, path or extension ID in any dataset |
| Telegram, Discord | `tdata`, `discordcanary`, `discordptb`, `dQw4w9WgXcQ:`, token regexes, `leveldb`, webhook URLs | **0** (whole-word `tdata` in the datasets: 0; the substring hits, checked file by file, are "metadata"-like words) | none |
| FileZilla, Steam, VPN | `recentservers.xml`, `sitemanager.xml`, `ssfn`, `loginusers.vdf`, `NordVPN`, `ProtonVPN`, `OpenVPN` | `OpenVPN` 4 (product name in vocabulary and `fields.json`); others 0 | |
| RedLine recon | `ipinfo.io`, `api.ip.sb`, `api.ipify.org`, `ip-api.com`, `Win32_VideoController`, `Win32_Processor` | **0** | |

So the datasets mention stealers only descriptively, in ATT&CK and MISP prose. They contain none of the
paths, IDs or regexes that stealers (and RedLine detections) key on, apart from one documented Chrome `Login Data` path
and the `CryptUnprotectData` function name, both inside the ATT&CK T1555.003 (Credentials from Web
Browsers) description. The same counts appear in the Windows, Linux and wasm builds because they come from the
shared vocabulary; the Linux CLI binary additionally carries one whole-word `tdata` (source not traced).

Per binary (before and after the compression experiment of section 5, `V4` = all 337 datasets deflated):

| Class | CLI exe V0 | CLI exe V4 | LSP exe V0 → V4 | `.pyd` V0 → V4 |
|---|---:|---:|---|---|
| RedLine / Lumma / Vidar / StealC | 2 / 6 / 2 / 1 | **0** | 2/6/2/1 → 0 | 2/6/2/1 → 0 |
| `stealer` (any case) | 62 | **0** | 62 → 0 | 62 → 0 |
| `Login Data`, `CryptUnprotectData` | 1, 2 | **0, 0** | 1, 2 → 0 | 1, 2 → 0 |
| `Cookies` word / `OpenVPN` | 14 / 4 | **0 / 0** | 14/4 → 0 | 14/4 → 0 |

### 9.3 Does option (a) cover it?

For the string and rule-based families: yes. After deflating all datasets, none of the stealer strings above
survives in plain text in the CLI exe, the LSP exe or the `.pyd`, and 0 rules hit in YARA-Forge (all 11 852),
signature-base or Elastic (V0 CLI exe had six Forge rules; V4 has none; the LSP exe and `.pyd` likewise).

What stays in plain text, and what compression does not touch (printable strings of the compressed CLI exe,
432 117 strings; counts case-insensitive):

| Residual | Count / content | Where it comes from | Risk |
|---|---|---|---|
| Credential vocabulary | `token` 111, `credential` 70, `api key` 24, `password` 8, `cookie` 4 | connectors and schema field names, TLS library error names, the TUI redaction pattern `(?i)(secret|token|password|passwd|passphrase|api[_\-\s.]?key|private[_\-\s.]?key|credential|auth|^key$|[_\-\s.]key$|cookie|session)`, deploy-action docs ("force a password reset") | low: no store path, no wallet or browser word |
| Google ADC path | `APPDATA`, `LOCALAPPDATA`, `gcloud`, `application_default_credentials.json`, `GOOGLE_APPLICATION_CREDENTIALS` | `crates/opentide-connectors/src/google_secops/auth.rs` (ADC lookup in Google's order) | moderate: the strings "read a credentials file in AppData" are the one code-side pattern near a stealer's behaviour |
| Git and SSH | `git config core.sshCommand "ssh -i \"$OPENTIDE_PUSH_SSH_KEY\" ...`, `.ssh` ×1, `libexec/git-core`, `git.exe` | push/share helper | low |
| Process and shell | `powershell` 5, `cmd.exe` 4 | CLI helpers | low |
| Other literals | `wallet`, `chrome`, `firefox`, `keychain`, `keyring`, `dpapi`, `discord`, `telegram`, `id_rsa`, `.aws`, `netrc`, `webhook`, `ipify` | all **0** | none |
| **Imports (not strings)** | CLI exe and `.pyd`: user32 `GetForegroundWindow`, `GetWindowThreadProcessId`, `GetKeyboardLayout`, `ToUnicodeEx`; advapi32 `OpenProcessToken`, `GetTokenInformation`, `CheckTokenMembership`; crypt32 only the certificate-store calls (`CertOpenStore`, `CertEnumCertificatesInStore`, ...) | the user32 set comes from `termina` 0.3.3 (`src/parse/windows.rs`), a terminal-input crate that `Cargo.lock` lists as a dependency of `opentide-cli` and `ratatui-termina` (the terminal UI and prompts; whether it can be feature-gated out was not checked) | **the one residual that heuristics could read as keylogging**: foreground-window plus keyboard-layout plus `ToUnicodeEx` is the classic key-translation set. The LSP exe imports none of user32. No `CryptUnprotectData` and no `mscoree` import; no .NET (CLR) header (the Data Directory 14 size is 0 in all three), so a `Trojan:MSIL/RedLine...` verdict cannot match this native Rust code on structure |

Compression therefore removes the string evidence and leaves two code-side signals: the Google ADC path
strings and, in the CLI exe and `.pyd` only, the user32 key-translation imports (from the terminal UI
feature). If a cloud ML verdict persists after (a), the next levers are: check whether the terminal-input
dependency can be gated behind a feature or split into a separate binary (the LSP exe already has no user32
imports); the evidence for this is the import list above, not a Defender result.

### 9.4 Likely Defender verdict families and what to put in the WDSI submission

Microsoft's [malware naming page](https://learn.microsoft.com/en-us/defender-xdr/malware-naming) says a
suffix beginning with `!` is an internal indicator and lists only `!rfn`; it does not define `!ml` or
`!MTB`. The meanings below are the community's and are labelled as such. The exact Defender detection name,
the file's SHA-256 and the engine and signature versions are needed from the owner before any of this can
be settled: the report on file gives only "RedLine".

| Verdict form | What it most likely implies (community reading) | Fit with the evidence | WDSI text |
|---|---|---|---|
| `Trojan:Win32/RedLine.<x>` without a suffix, or `Trojan:MSIL/RedLine.<x>` | a byte or behaviour signature for the RedLine family; `MSIL` means a .NET assembly | **No fit on structure:** no CLR header, no .NET metadata (`BSJB` count 0), 0 RedLine rules hit; a `MSIL` name on a native Rust PE would itself be a mismatch to point out | state that the file is a native Rust x64 PE with no .NET header and that 25 public RedLine rules (Elastic, YARA-Forge, signature-base) and 8 ReversingLabs infostealer rules produce no match; give the PE section and import facts (9.3); ask for the matched signature or the sample it was derived from |
| `...!MTB` (e.g. `Trojan:Win32/RedLine.MC!MTB`) | commonly read as a machine-learning or cloud-classification verdict tied to a family label, not a byte signature (not defined by Microsoft; Trend Micro lists `Trojan:MSIL/RedLine.MC!MTB` as a Microsoft alias for RedLine) | plausible trigger: a very large PE with 11 MB of mixed credential, miner, C2 and injection vocabulary in `.rdata`, unsigned, and the user32 key-translation imports | say it is a false positive of a classification verdict; explain the dataset content (MITRE ATT&CK and MISP descriptions, Falco default rules, malapi) as detection content, link the public source repository, the licence, and the build provenance; after (a) and the signing steps resubmit the new hash |
| `...!ml` | machine-learning detection (Microsoft Q&A and Rust forum reports of `Bearfoos.A!ml`, `Wacatac.B!ml` on Rust binaries) | plausible: unsigned large Rust PE with no reputation | report as an ML false positive; unsigned and new binaries start without reputation, so signing and consistent publishing matter as much as the content |
| `...!rfn`, `...!pz` and other reputation suffixes | reputation or prevalence verdicts, not content | applies to every new unsigned release hash | ask for the hash to be allowed or its reputation reviewed after signing |
| `Behavior:Win32/...` or `Trojan:Script/...` | runtime behaviour in the clean-room or on the endpoint | not testable here: no process, network or file-system behaviour was exercised | describe what `opentide` does at runtime (reads its repository, calls vendor HTTP APIs with user-provided credentials, and for Google SecOps reads the ADC file); provide the command line used when Defender fired |

What every submission should carry: the exact detection name and the Defender product, engine and
signature versions; the file's SHA-256 (the release `SHA256SUMS`); the download URL; the sentence that the
file is a developer tool that embeds public detection content; the facts from sections 4, 5 and 9 (no stealer
store, wallet or browser paths; no RedLine rule matches; no .NET header); and, once available, the compressed
rebuild's hash. Submit each distinct hash separately (each `exe`, the LSP, the wheels' `.pyd`), and keep the
Marketplace appeal (section 7) and the Defender submissions pointing at the same evidence.

### 9.5 Revised recommendation

Section 8 stands, with two additions: (a) now also covers the stealer-vocabulary families, so the compression
work should land before the next Windows release; and (7) review the Windows CLI's user32 key-translation
imports (the `termina` dependency) and the Google ADC string path, since compression does not touch them.
Open items: the exact Defender detection name and hash from the owner; a run against Defender itself, which
only the owner can do.

## Appendix: commands

```bash
apt-get install -y clamav clamav-freshclam yara p7zip-full zstd
CURL_CA_BUNDLE=/etc/ssl/certs/ca-bundle.pem freshclam          # needs a CA path freshclam can read
clamscan -r --scan-archive=yes --max-filesize=900M --max-scansize=4000M \
         --max-recursion=30 --alert-exceeds-max=yes -d /var/lib/clamav DIR
sigtool --find-sigs 'Win.Coinminer.Generic-7150608-0'           # the signature definition
yara -C -p 4 -w -s -L --scan-list bundle.yarc FILELIST          # bundle = yarac of every rule file that compiles
# externals for signature-base: -d filename=x.exe -d filepath=/x/x.exe -d extension=.exe -d filetype=EXE -d owner=x
```

Causality variants were produced by locating each dataset by exact bytes (LF and CRLF), replacing it in a
copy with `zlib.compress(level 9)` plus zero padding, an XOR, or a defanged string, then rescanning. The
scripts and the artifacts are in the session scratchpad and are not part of this branch.
