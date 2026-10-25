#!/usr/bin/env python3
"""Build crates/junction-check/data/catalog.json: the subset of Junction's catalogue the check packs call.

The full catalogue is hundreds of megabytes and regenerated daily. Checks call a few dozen
operations, so this script copies only the operations listed in
crates/junction-check/data/operations.txt, with the schema definitions their request inputs
reference, into one RegistryManifest the binary embeds at build time. Response schemas are
dropped: checks read responses as JSON and never validate them against the catalogue.

Usage:
    scripts/check-catalog.py /path/to/generated/registry

The registry directory is the `generated/registry` folder of a release bundle
(`endpoint-catalogs.tar.gz`) or of a local `scripts/update-catalogs.sh` run. Re-run after
editing operations.txt and commit the result. A unit test fails if the two drift apart.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "crates" / "junction-check" / "data"
OPS_FILE = DATA / "operations.txt"
OUT_FILE = DATA / "catalog.json"
REF = re.compile(r"^#/(.+)$")


def wanted() -> list[tuple[str, bool]]:
    out = []
    for line in OPS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        op, _, variant = line.partition("@")
        if variant not in ("", "beta"):
            raise SystemExit(f"unknown variant in {line!r}")
        out.append((op, variant == "beta"))
    return out


def walk_refs(node, found: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            m = REF.match(ref)
            if m:
                found.add(m.group(1))
        for v in node.values():
            walk_refs(v, found)
    elif isinstance(node, list):
        for v in node:
            walk_refs(v, found)


def resolve_pointer(schemas, pointer: str):
    node = schemas
    for part in pointer.split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def set_pointer(target, pointer: str, value) -> None:
    parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")]
    node = target
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


# Defender for Endpoint list APIs page with OData `@odata.nextLink` (10,000 items per page,
# https://learn.microsoft.com/defender-endpoint/api/get-machines), but the published
# specification does not declare it, so the runtime would stop after the first page.
MDE_PAGED = {
    "defender.endpoint.machines.list",
    "defender.endpoint.machines.list_secure_configurations_assessment_by_machine",
    "defender.endpoint.machines.list_software_inventory_by_machine",
    "defender.endpoint.vulnerabilities.list_machines_vulnerabilities",
    "defender.endpoint.recommendations.list",
}


def declare_paging(op: dict) -> dict:
    if op["id"] in MDE_PAGED and op["method"] == "GET" and not op.get("pageable"):
        op = dict(op)
        op["pageable"] = {"item_name": "value", "next_link_name": "@odata.nextLink", "operation_name": None}
    return op


def strip_responses(op: dict) -> dict:
    op = dict(op)
    op["responses"] = {
        code: {"description": (resp or {}).get("description", "")}
        for code, resp in (op.get("responses") or {}).items()
    }
    return op


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    registry_dir = Path(sys.argv[1])
    if not (registry_dir / "operations.json").is_file():
        print(f"{registry_dir}/operations.json not found", file=sys.stderr)
        return 2

    entries = wanted()
    stable = {op for op, beta in entries if not beta}
    beta = {op for op, is_beta in entries if is_beta}
    operations: list[dict] = []
    schemas: dict = {}
    sources: set[str] = set()

    def take(manifest_path: Path, ids: set[str], preview: bool) -> None:
        manifest = json.loads(manifest_path.read_text())
        file_schemas = manifest.get("schemas") or {}
        for op in manifest.get("operations", []):
            if op["id"] not in ids or bool(op.get("preview")) != preview:
                continue
            ids.discard(op["id"])
            sources.add(manifest_path.name)
            op = declare_paging(strip_responses(op))
            operations.append(op)
            refs: set[str] = set()
            walk_refs(op, refs)
            seen: set[str] = set()
            while refs - seen:
                pointer = (refs - seen).pop()
                seen.add(pointer)
                value = resolve_pointer(file_schemas, pointer)
                if value is None:
                    continue
                set_pointer(schemas, pointer, value)
                walk_refs(value, refs)

    take(registry_dir / "operations.json", stable, False)
    if beta:
        take(registry_dir / "graph-beta.json", beta, True)
    missing = sorted(stable | beta)
    if missing:
        print("operations not found:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1
    operations.sort(key=lambda op: (op["id"], op.get("api_version") or ""))
    out = {
        "format_version": 1,
        "operations": operations,
        "schemas": schemas,
    }
    OUT_FILE.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT_FILE.relative_to(ROOT)}: {len(operations)} operations from {sorted(sources)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
