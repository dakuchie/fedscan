"""Create blinded labelling sheets for the independent validation (paper Sect. 5.3).

    python make_label_sheets.py --scan data/gh_scan.jsonl --out submission/validation --n-random 150

Sample: every production CI binding that FedScan rates T-class or U, plus a simple random sample of the
remaining production CI bindings (seeded, reproducible). Produces:
  rater1.csv, rater2.csv   identical blinded sheets (no FedScan verdicts) - one per rater
  key.csv                  FedScan verdicts per binding_id (do NOT give to raters)
After labelling, merge into data/labels.csv with columns binding_id, rater1, rater2, adjudicated.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

FIELDS = ["binding_id", "repository", "file", "line", "resource", "link", "label", "notes"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--n-random", type=int, default=150)
    ap.add_argument("--seed", type=int, default=20261017)
    a = ap.parse_args()

    rows = []
    with open(a.scan, encoding="utf-8") as f:
        for i, line in enumerate(f):
            d = json.loads(line)
            if d.get("scope") != "ci" or d.get("path_is_example"):
                continue
            codes = [x["flaw"] for x in d["findings"]]
            d["binding_id"] = i                     # = row index, the id analyze.py uses
            d["stratum"] = "flagged" if any(c[0] == "T" or c == "U" for c in codes) else "other"
            d["tool_codes"] = ";".join(codes) or "OK"
            rows.append(d)
    flagged = [r for r in rows if r["stratum"] == "flagged"]
    others = [r for r in rows if r["stratum"] == "other"]
    rng = random.Random(a.seed)
    sample = flagged + rng.sample(others, min(a.n_random, len(others)))
    rng.shuffle(sample)                              # raters must not infer strata from order

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for rater in ("rater1", "rater2"):
        with open(out / f"{rater}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            for r in sample:
                sha = r.get("head") or "HEAD"
                path = r["file"].replace("\\", "/")
                w.writerow({"binding_id": r["binding_id"], "repository": r["repo"], "file": path,
                            "line": r["line"], "resource": r["resource"],
                            "link": f"https://github.com/{r['repo']}/blob/{sha}/{path}#L{r['line']}",
                            "label": "", "notes": ""})
    with open(out / "key.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["binding_id", "stratum", "tool_codes", "max_severity"])
        w.writeheader()
        for r in sample:
            w.writerow({k: r.get(k) for k in ("binding_id", "stratum", "tool_codes", "max_severity")})
    print(f"{len(sample)} bindings ({len(flagged)} flagged + {len(sample) - len(flagged)} random) -> {out}")


if __name__ == "__main__":
    main()
