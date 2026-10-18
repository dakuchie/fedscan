"""fedscan command-line interface.

    fedscan scan PATH [--format text|jsonl|sarif] [--min-severity low] [--repo-id ID]

Exit code 1 if any finding at or above --fail-on (default: high) is reported, so the tool can gate CI.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, scan
from .model import Severity
from .rules import TAXONOMY


def _sarif(results, root: str) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = [{"id": k, "name": v[0].replace(" ", ""), "shortDescription": {"text": v[0]},
              "fullDescription": {"text": v[1]}} for k, v in TAXONOMY.items()]
    items = []
    for r in results:
        for f in r.findings:
            items.append({
                "ruleId": f.flaw, "level": level[f.severity.value],
                "message": {"text": f"[{f.severity.value}] {r.binding.resource}: {f.message}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": r.binding.file.replace("\\", "/")},
                    "region": {"startLine": max(r.binding.line, 1)}}}],
                "properties": {"security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5",
                                                     "low": "3.0", "info": "0.0"}[f.severity.value]},
            })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "fedscan", "version": __version__,
                                          "informationUri": "https://github.com/dakuchie/fedscan",
                                          "rules": rules}},
                      "results": items}]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fedscan", description="Static analyzer for CI/CD-to-cloud OIDC trust policies")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--format", choices=["text", "jsonl", "sarif"], default="text")
    s.add_argument("--min-severity", choices=[x.value for x in Severity], default="info")
    s.add_argument("--fail-on", choices=[x.value for x in Severity] + ["never"], default="high")
    s.add_argument("--repo-id", default=None, help="identifier copied into jsonl records (measurement runs)")
    sub.add_parser("taxonomy", help="print the flaw taxonomy")
    a = ap.parse_args(argv)

    if a.cmd == "taxonomy":
        for k, (name, desc) in TAXONOMY.items():
            print(f"{k:3} {name}\n    {desc}")
        return 0

    results, errors = scan(a.path)
    floor = Severity(a.min_severity).rank
    if a.format == "jsonl":
        for r in results:
            d = r.to_dict()
            d["findings"] = [f for f in d["findings"] if Severity(f["severity"]).rank >= floor]
            d["repo_id"] = a.repo_id
            print(json.dumps(d, ensure_ascii=False))
        for path, err in errors:
            print(json.dumps({"repo_id": a.repo_id, "parse_error": err, "file": path}), file=sys.stderr)
    elif a.format == "sarif":
        print(json.dumps(_sarif(results, a.path), indent=2))
    else:
        if not results:
            print("No OIDC trust bindings found.")
        for r in results:
            b = r.binding
            shown = [f for f in r.findings if f.severity.rank >= floor]
            head = f"{b.file}:{b.line}  {b.resource}  [{b.provider.value}, issuer={b.issuer}]"
            print(head + ("" if shown else "  OK"))
            for f in shown:
                print(f"    {f.severity.value.upper():8} {f.flaw:3} {f.name}: {f.message}"
                      + (f"  ({f.evidence})" if f.evidence else ""))
        for path, err in errors:
            print(f"parse error: {path}: {err}", file=sys.stderr)

    if a.fail_on == "never":
        return 0
    gate = Severity(a.fail_on).rank
    return 1 if any(f.severity.rank >= gate for r in results for f in r.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
