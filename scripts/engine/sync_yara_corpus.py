#!/usr/bin/env python3
"""Vendor the public YARA rules of the external corpus (#165).

Copies each listed file, unmodified, from two checkouts into
``crates/testdata/conformance/external/yara/<source>/`` and writes its ``.broken.``
twin: the same file with one injected fault, chosen by the file's place in
the list (an unterminated rule, an undefined string, a misspelled
``condition``, an undefined identifier). libyara must refuse every twin;
``yara-python`` 4.5.4 checks it here.

- ReversingLabs/reversinglabs-yara-rules (MIT) at ``RL_COMMIT``;
- Neo23x0/signature-base (Detection Rule License 1.1) at ``SB_COMMIT``. A
  file is taken only if every ``license`` meta it carries is the DRL 1.1:
  a rule under another licence (CC BY-NC, OGL, BSD, ...) stays out.

Nothing GPL or Elastic License is vendored. ``crates/opentide-yara/tests/
external_corpus.rs`` holds the engine to the files: every public file comes
out clean, every twin gets an error.

Usage:
    python -I scripts/engine/sync_yara_corpus.py --reversinglabs ../reversinglabs-yara-rules \
        --signature-base ../signature-base [--check]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "testdata" / "conformance" / "external" / "yara"

RL_COMMIT = "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84"
SB_COMMIT = "de3c7252c22b3376352b5a68defa46459a12a693"

REVERSINGLABS = [
    "yara/backdoor/ByteCode.MSIL.Backdoor.AgentRacoon.yara",
    "yara/backdoor/ByteCode.MSIL.Backdoor.AsyncRAT.yara",
    "yara/backdoor/ByteCode.MSIL.Backdoor.LimeRAT.yara",
    "yara/backdoor/ByteCode.MSIL.Backdoor.OrcusRAT.yara",
    "yara/backdoor/ByteCode.MSIL.Backdoor.ResolverRAT.yara",
    "yara/downloader/Win32.Downloader.dlMarlboro.yara",
    "yara/exploit/Win32.Exploit.CVE20200601.yara",
    "yara/infostealer/ByteCode.MSIL.Infostealer.GomorrahStealer.yara",
    "yara/infostealer/Win32.Infostealer.MultigrainPOS.yara",
    "yara/infostealer/Win32.Infostealer.ProjectHookPOS.yara",
    "yara/pua/Win32.PUA.Domaiq.yara",
    "yara/ransomware/ByteCode.MSIL.Ransomware.Apis.yara",
    "yara/ransomware/ByteCode.MSIL.Ransomware.ChupaCabra.yara",
    "yara/ransomware/ByteCode.MSIL.Ransomware.Cring.yara",
    "yara/ransomware/ByteCode.MSIL.Ransomware.Dusk.yara",
    "yara/ransomware/ByteCode.MSIL.Ransomware.EAF.yara",
    "yara/rootkit/Linux.Rootkit.Pumakit.yara",
    "yara/trojan/Linux.Trojan.AcidRain.yara",
    "yara/trojan/Linux.Trojan.BiBiWiper.yara",
    "yara/trojan/Win32.Trojan.BiBiWiper.yara",
    "yara/trojan/Win32.Trojan.CaddyWiper.yara",
    "yara/virus/Linux.Virus.Vit.yara",
    "yara/virus/Win32.Virus.Awfull.yara",
    "yara/virus/Win32.Virus.Cmay.yara",
    "yara/virus/Win32.Virus.DeadCode.yara",
]

SIGNATURE_BASE = [
    "yara/apt_aa19_024a.yar",
    "yara/apt_agent_btz.yar",
    "yara/bkdr_xz_util_cve_2024_3094.yar",
    "yara/crime_academic_data_centers_camp_may20.yar",
    "yara/crime_andromeda_jun17.yar",
    "yara/expl_adselfservice_cve_2021_40539.yar",
    "yara/expl_cleo_dec24.yar",
    "yara/exploit_cve_2014_4076.yar",
    "yara/gen_Excel4Macro_Sharpshooter.yar",
    "yara/general_officemacros.yar",
    "yara/generic_cryptors.yar",
    "yara/hktl_badsuccessor_helper_may25.yar",
    "yara/htkl_blue_hammer_tool.yar",
    "yara/log_teamviewer_keyboard_layouts.yar",
    "yara/lotusblossom_notepad_exploitation.yar",
    "yara/mal_avemaria_rat.yar",
    "yara/pua_cryptocoin_miner.yar",
    "yara/pup_lightftp.yar",
    "yara/react_pocs_indicators_dec25.yar",
    "yara/seaspy_backdoor_jan25.yar",
    "yara/susp_aur_packages.yar",
    "yara/threat_compromised_daemon_tools_lite_may26.yar",
    "yara/vul_backdoor_antitheftweb.yar",
    "yara/vuln_erlang_otp_ssh_cve_2025_32433.yar",
    "yara/webshell_regeorg.yar",
]

DRL = "Detection Rule License 1.1"


def broken(text: str, index: int) -> str:
    """`text` with fault number `index % 4`."""
    kind = index % 4
    if kind == 0:
        # The last rule's closing brace.
        end = text.rstrip().rfind("}")
        return text[:end] + text[end + 1 :]
    m = re.search(r"\bcondition\s*:", text)
    assert m, "no condition"
    if kind == 1:
        return text[: m.end()] + " $opentide_undefined or" + text[m.end() :]
    if kind == 2:
        return text[: m.start()] + "conditon:" + text[m.end() :]
    return text[: m.end()] + " opentide_undefined or" + text[m.end() :]


def refused(source: str) -> bool:
    import yara

    try:
        yara.compile(source=source)
    except yara.SyntaxError:
        return True
    return False


def head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reversinglabs", type=Path, required=True)
    ap.add_argument("--signature-base", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    sources = [
        ("reversinglabs", args.reversinglabs, RL_COMMIT, REVERSINGLABS),
        ("signature-base", args.signature_base, SB_COMMIT, SIGNATURE_BASE),
    ]
    files: dict[Path, str] = {}
    for name, checkout, commit, listed in sources:
        if head(checkout) != commit:
            print(f"{checkout} is not at {commit}", file=sys.stderr)
            return 2
        for index, rel in enumerate(listed):
            text = (checkout / rel).read_text(encoding="utf-8")
            if name == "signature-base":
                for lic in re.findall(r'\blicense\s*=\s*"([^"]*)"', text):
                    if DRL not in lic:
                        print(f"{rel}: licence {lic!r} is not the DRL 1.1", file=sys.stderr)
                        return 1
            twin = broken(text, index)
            if not refused(twin):
                print(f"{rel}: libyara compiles the broken twin", file=sys.stderr)
                return 1
            path = OUT / name / Path(rel).name
            stem, ext = path.name.rsplit(".", 1)
            files[path] = text
            files[path.with_name(f"{stem}.broken.{ext}")] = twin
    if args.check:
        on_disk = {p for p in OUT.rglob("*") if p.is_file() and p.parent != OUT}
        stale = [
            p for p, t in files.items() if not p.exists() or p.read_text(encoding="utf-8") != t
        ]
        stale += sorted(on_disk - set(files))
        for p in stale:
            print(f"{p.relative_to(ROOT)} is stale", file=sys.stderr)
        return 1 if stale else 0
    for p, t in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(t, encoding="utf-8")
    print(f"wrote {len(files)} files to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
