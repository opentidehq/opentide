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
