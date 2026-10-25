#!/usr/bin/env python3
"""One-way sync of framework data from crownguard into junction-check (see sync-frameworks.sh).

Writes crates/junction-check/data/frameworks/{essential-eight,ism,cis-m365,nist-csf-2}.yaml.
cis-controls-v8.yaml and mitre-attack.yaml are maintained in this repository (crownguard has
no copy) and are left untouched.

Essential Eight requirements come from the ISM: every ISM control carrying an `e8` attribute
is a maturity-model requirement at those levels. Its strategy is chosen from the ISM topic
(and, for shared topics such as event logging, from the control statement) by the explicit
rules below, so the mapping is reviewable in one place.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "crates" / "junction-check" / "data" / "frameworks"

STRATEGIES = [
    ("patch-applications", "Patch applications"),
    ("patch-operating-systems", "Patch operating systems"),
    ("mfa", "Multi-factor authentication"),
    ("restrict-admin-privileges", "Restrict administrative privileges"),
    ("application-control", "Application control"),
    ("office-macros", "Restrict Microsoft Office macros"),
    ("user-application-hardening", "User application hardening"),
    ("regular-backups", "Regular backups"),
]

TOPIC = {
    "Application control": ["application-control"],
    "Multi-factor authentication": ["mfa"],
    "Privileged access to systems": ["restrict-admin-privileges"],
    "Separate privileged operating environments": ["restrict-admin-privileges"],
    "Administrative infrastructure": ["restrict-admin-privileges"],
    "Suspension of access to systems": ["restrict-admin-privileges"],
    "Protecting credentials": ["restrict-admin-privileges"],
    "Setting credentials for built-in Administrator accounts, break glass accounts, local administrator accounts and service accounts": ["restrict-admin-privileges"],
    "Backup access": ["regular-backups"],
    "Backup modification and deletion": ["regular-backups"],
    "Performing and retaining backups": ["regular-backups"],
    "Testing restoration of backups": ["regular-backups"],
    "Web browsers": ["user-application-hardening"],
    "Portable Document Format applications": ["user-application-hardening"],
    "PowerShell": ["user-application-hardening"],
    "Command Shell": ["user-application-hardening"],
    "Hardening operating system configurations": ["user-application-hardening"],
}
# Event logging and incident handling requirements recur under four strategies.
LOGGING = ["application-control", "restrict-admin-privileges", "user-application-hardening", "mfa"]


def strategies_for(topic: str, title: str) -> list[str]:
    t = title.lower()
    if topic in TOPIC:
        return TOPIC[topic]
    if topic == "Office productivity suites":
        return ["office-macros"] if "macro" in t else ["user-application-hardening"]
    if topic in ("Mitigating known vulnerabilities", "Vulnerability scanning", "Cessation of support",
                 "Operating system releases and versions"):
        os_ = "operating system" in t or "firmware" in t or "drivers" in t
        apps = any(w in t for w in ("application", "office", "browser", "pdf", "email client", "security product"))
        if os_ and not apps:
            return ["patch-operating-systems"]
        if apps and not os_:
            return ["patch-applications"]
        return ["patch-applications", "patch-operating-systems"]
    if topic in ("Event log monitoring", "Centralised event logging facility", "Enacting cyber security incident response plans",
                 "Reporting cyber security incidents", "Reporting cyber security incidents to ASD"):
        if "privileged" in t:
            return ["restrict-admin-privileges"]
        if "multi-factor" in t:
            return ["mfa"]
        if "application control" in t:
            return ["application-control"]
        if "powershell" in t or "command line" in t:
            return ["user-application-hardening"]
        return LOGGING
    raise SystemExit(f"no Essential Eight strategy rule for ISM topic {topic!r}; add one to TOPIC")


def q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_ism(text: str) -> list[dict]:
    out = []
    for block in text.split("\n  - id: ")[1:]:
        cid = block.split("\n", 1)[0].strip().strip('"')
        group = re.search(r'\n    group: "?(.*?)"?\n', block)
        title = re.search(r'\n    title: "?(.*?)"?\n', block)
        e8 = re.search(r"\n    e8: \[(.*?)\]", block)
        out.append({
            "id": cid,
            "group": group.group(1) if group else "",
            "title": title.group(1).replace('\\"', '"') if title else "",
            "e8": [int(x.strip()[2:]) for x in e8.group(1).split(",")] if e8 else [],
        })
    return out


def header(lines: list[str], crownguard_rev: str) -> list[str]:
    return [f"# Generated by scripts/sync-frameworks.sh from crownguard {crownguard_rev}. Do not edit by hand.", *lines]


def main() -> int:
    cg = Path(sys.argv[1])
    frameworks = cg / "content" / "frameworks"
    try:
        rev = subprocess.check_output(["git", "-C", str(cg), "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        rev = "(unknown revision)"
    ism_text = (frameworks / "ism.yaml").read_text()
    version = re.search(r"catalog version ([0-9.]+)", ism_text)
    ism_version = version.group(1) if version else "unknown"
    controls = parse_ism(ism_text)

    # ISM: ids and shortened statements.
    lines = header([
        "id: ism",
        "name: Australian Government Information Security Manual",
        f"version: {q(ism_version)}",
        "source: https://github.com/AustralianCyberSecurityCentre/ism-oscal",
        "licence: >-",
        "  Control statements shortened to 140 characters by crownguard. © Commonwealth of Australia,",
        "  licensed CC BY 4.0 (Coat of Arms and ASD logo excepted).",
        "controls:",
    ], rev)
    for c in controls:
        lines += [f"  - id: {c['id']}", f"    title: {q(c['title'])}"]
    (OUT / "ism.yaml").write_text("\n".join(lines) + "\n")

    # Essential Eight strategies and ISM-derived requirements.
    reqs: dict[str, list[dict]] = {s: [] for s, _ in STRATEGIES}
    for c in controls:
        if not c["e8"]:
            continue
        topic = c["group"].split(" / ")[-1]
        for s in strategies_for(topic, c["title"]):
            reqs[s].append(c)
    lines = header([
        "id: essential-eight",
        "name: ASD Essential Eight Maturity Model",
        f"version: {q('November 2023 (requirements from ISM ' + ism_version + ')')}",
        "source: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        "licence: >-",
        "  Requirements are the ISM controls ASD tags with Essential Eight maturity levels. © Commonwealth of",
        "  Australia, licensed CC BY 4.0 (Coat of Arms and ASD logo excepted). Strategy assignment is",
        "  Junction's mapping (scripts/sync-frameworks.py) and is indicative.",
        "strategies:",
    ], rev)
    for sid, title in STRATEGIES:
        lines += [f"  - id: {sid}", f"    title: {q(title)}", "    requirements:"]
        if not reqs[sid]:
            lines[-1] += " []"
        for c in reqs[sid]:
            lines += [f"      - id: {c['id']}", f"        levels: [{', '.join(str(l) for l in c['e8'])}]"]
    (OUT / "essential-eight.yaml").write_text("\n".join(lines) + "\n")

    # CIS M365: recommendation numbers only (CIS Benchmarks are CC BY-NC-SA 4.0).
    cis = (frameworks / "cis-m365.yaml").read_text()
    name = re.search(r"\nname: (.*)\n", cis).group(1)
    ids = re.findall(r'\n  - id: "?([0-9.]+)"?\n', cis)
    lines = header([
        "id: cis-m365",
        f"name: {q(name)}",
        f"version: {q(name.split()[-1])}",
        "source: https://www.cisecurity.org/benchmark/microsoft_365",
        "licence: >-",
        "  CIS Benchmarks are licensed CC BY-NC-SA 4.0. Only recommendation numbers are recorded; get the",
        "  benchmark from CIS for titles, rationale and audit steps.",
        "controls:",
    ], rev)
    lines += [f"  - id: {q(i)}" for i in ids]
    (OUT / "cis-m365.yaml").write_text("\n".join(lines) + "\n")

    # NIST CSF 2.0: public domain.
    nist = (frameworks / "nist-csf-2.yaml").read_text()
    entries = [(c["id"], c["title"]) for c in parse_ism(nist)]
    lines = header([
        "id: nist-csf-2",
        "name: NIST Cybersecurity Framework 2.0",
        'version: "2.0"',
        "source: https://doi.org/10.6028/NIST.CSWP.29",
        "licence: NIST publications are in the public domain in the United States.",
        "controls:",
    ], rev)
    for cid, title in entries:
        lines += [f"  - id: {cid}", f"    title: {q(title)}"]
    (OUT / "nist-csf-2.yaml").write_text("\n".join(lines) + "\n")

    total = sum(len(v) for v in reqs.values())
    print(f"ism {len(controls)} controls; essential eight {total} strategy requirements; cis-m365 {len(ids)} ids; nist {len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
