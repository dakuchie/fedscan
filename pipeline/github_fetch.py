"""Fetch only the IaC files in matched directories via GitHub GraphQL (batched), pinned to each
repository's default-branch commit. Much cheaper than cloning or downloading archives at census scale.

    python github_fetch.py --candidates data/gh_candidates.jsonl --dest data/gh_repos [--limit N]

Writes <dest>/<owner>__<repo>/... (IaC files only), a .fedscan_source marker per repository, and
<dest>/repos.csv with repository metadata (stars, forks, owner type, dates, archived/fork flags).
Downloaded files are data: they are parsed, never executed. Resumable: finished repositories are skipped.
Token: GITHUB_TOKEN (see collect.github_token); its value is never printed.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path, PurePosixPath

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect import github_token  # noqa: E402

GQL = "https://api.github.com/graphql"
IAC_SUFFIXES = (".tf", ".tofu", ".tfvars", ".yaml", ".yml", ".json", ".template")
MAX_FILE = 2_000_000
META_FIELDS = ["repo", "head", "stars", "forks", "owner_type", "created_at", "pushed_at", "archived", "fork"]


class Client:
    def __init__(self):
        tok = github_token()
        if not tok:
            sys.exit("GITHUB_TOKEN is required")
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {tok}", "User-Agent": "oidc-trust-study"})

    def query(self, q: str) -> dict:
        delay = 5
        for _ in range(10):
            try:
                r = self.s.post(GQL, json={"query": q}, timeout=120)
            except requests.RequestException as e:
                print(f"network error {e}; retry in {delay}s", file=sys.stderr)
                time.sleep(delay); delay = min(delay * 2, 300); continue
            if r.status_code in (502, 503, 504) or (r.status_code == 403 and "rate" in r.text.lower()):
                reset = int(r.headers.get("x-ratelimit-reset", time.time() + delay))
                wait = max(reset - int(time.time()), delay) if r.status_code == 403 else delay
                print(f"HTTP {r.status_code}; waiting {wait}s", file=sys.stderr)
                time.sleep(wait); delay = min(delay * 2, 300); continue
            r.raise_for_status()
            body = r.json()
            remaining = int(r.headers.get("x-ratelimit-remaining", "1000"))
            if remaining < 50:
                wait = max(int(r.headers.get("x-ratelimit-reset", time.time() + 60)) - int(time.time()), 5)
                print(f"rate budget low ({remaining}); sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
            return body.get("data") or {}
        raise RuntimeError("GraphQL query failed repeatedly")


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def batched(xs, n):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]


def fetch_metadata(c: Client, repos: list[str]) -> dict[str, dict]:
    meta = {}
    for chunk in batched(repos, 50):
        parts = []
        for i, full in enumerate(chunk):
            owner, name = full.split("/", 1)
            parts.append(f'r{i}: repository(owner: "{esc(owner)}", name: "{esc(name)}") {{ '
                         "stargazerCount forkCount isFork isArchived createdAt pushedAt "
                         "owner { __typename } defaultBranchRef { target { oid } } }")
        data = c.query("query {" + " ".join(parts) + "}")
        for i, full in enumerate(chunk):
            d = data.get(f"r{i}")
            if not d or not d.get("defaultBranchRef"):
                continue
            meta[full] = {"repo": full, "head": d["defaultBranchRef"]["target"]["oid"],
                          "stars": d["stargazerCount"], "forks": d["forkCount"],
                          "owner_type": d["owner"]["__typename"], "created_at": d["createdAt"],
                          "pushed_at": d["pushedAt"], "archived": d["isArchived"], "fork": d["isFork"]}
    return meta


def list_dirs(c: Client, items: list[tuple[str, str, str]]) -> dict[int, list[tuple[str, int]]]:
    """items: (repo, oid, dir) -> {index: [(path, size)]} of IaC blobs directly in dir."""
    out: dict[int, list[tuple[str, int]]] = {}
    for start in range(0, len(items), 25):
        chunk = items[start:start + 25]
        parts = []
        for k, (full, oid, d) in enumerate(chunk):
            owner, name = full.split("/", 1)
            expr = f"{oid}:{d}" if d else f"{oid}:"
            parts.append(f'd{k}: repository(owner: "{esc(owner)}", name: "{esc(name)}") {{ '
                         f'object(expression: "{esc(expr)}") {{ ... on Tree {{ entries {{ name type '
                         "object { ... on Blob { byteSize isBinary } } } } } }")
        data = c.query("query {" + " ".join(parts) + "}")
        for k, (full, oid, d) in enumerate(chunk):
            obj = ((data.get(f"d{k}") or {}).get("object") or {})
            files = []
            for e in obj.get("entries") or []:
                blob = e.get("object") or {}
                if e["type"] == "blob" and e["name"].endswith(IAC_SUFFIXES) and not blob.get("isBinary") \
                        and (blob.get("byteSize") or 0) <= MAX_FILE:
                    files.append((f"{d}/{e['name']}" if d else e["name"], blob.get("byteSize") or 0))
            out[start + k] = files
    return out


def fetch_blobs(c: Client, items: list[tuple[str, str, str]]) -> dict[int, str]:
    """items: (repo, oid, path) -> {index: text}. Batches by approximate payload size."""
    out: dict[int, str] = {}
    for start in range(0, len(items), 40):
        chunk = items[start:start + 40]
        parts = []
        for k, (full, oid, p) in enumerate(chunk):
            owner, name = full.split("/", 1)
            parts.append(f'b{k}: repository(owner: "{esc(owner)}", name: "{esc(name)}") {{ '
                         f'object(expression: "{esc(oid + ":" + p)}") {{ ... on Blob {{ text }} }} }}')
        data = c.query("query {" + " ".join(parts) + "}")
        for k in range(len(chunk)):
            text = (((data.get(f"b{k}") or {}).get("object")) or {}).get("text")
            if text is not None:
                out[start + k] = text
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--dest", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--max-mb", type=float, default=0, help="stop once the destination holds this many MB")
    a = ap.parse_args()

    dirs: dict[str, set[str]] = {}
    for line in open(a.candidates, encoding="utf-8"):
        c = json.loads(line)
        if c.get("fork") and not a.include_forks:
            continue
        d = str(PurePosixPath(c["path"]).parent)
        dirs.setdefault(c["repo"], set()).add("" if d == "." else d)
    repos = sorted(dirs)[: a.limit or None]
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    client = Client()

    meta_path = dest / "repos.csv"
    known = {}
    if meta_path.exists():
        known = {r["repo"]: r for r in csv.DictReader(open(meta_path, encoding="utf-8"))}
    todo_meta = [r for r in repos if r not in known]
    print(f"{len(repos)} repositories; fetching metadata for {len(todo_meta)}", file=sys.stderr, flush=True)
    for chunk in batched(todo_meta, 500):
        known.update(fetch_metadata(client, chunk))
        with open(meta_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=META_FIELDS)
            w.writeheader()
            w.writerows(known.values())

    pending = [r for r in repos if r in known and not (dest / r.replace("/", "__") / ".fedscan_source").exists()]
    print(f"fetching files for {len(pending)} repositories", file=sys.stderr, flush=True)
    t0 = time.time()
    done_bytes = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file()) if a.max_mb else 0
    for n, chunk in enumerate(batched(pending, 40), 1):
        items = [(r, known[r]["head"], d) for r in chunk for d in sorted(dirs[r])]
        listing = list_dirs(client, items)
        blobs = [(items[i][0], items[i][1], p) for i, files in listing.items() for p, _ in files]
        texts = fetch_blobs(client, blobs)
        for i, (full, oid, p) in enumerate(blobs):
            if i not in texts or ".." in p.split("/"):
                continue
            target = dest / full.replace("/", "__")
            out = (target / p).resolve()
            if target.resolve() not in out.parents:
                continue  # path traversal guard
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(texts[i], encoding="utf-8")
            done_bytes += len(texts[i])
        for full in chunk:
            target = dest / full.replace("/", "__")
            target.mkdir(parents=True, exist_ok=True)
            (target / ".fedscan_source").write_text(json.dumps({"repo": full, "sha": known[full]["head"],
                                                                "via": "github"}), encoding="utf-8")
        if a.max_mb and done_bytes / 1e6 >= a.max_mb:
            print(f"STOPPED: size cap of {a.max_mb:.0f} MB reached after {min(n * 40, len(pending))} repositories "
                  f"(resumable; raise --max-mb to continue)", file=sys.stderr, flush=True)
            break
        if n % 5 == 0 or n * 40 >= len(pending):
            rate = n * 40 / max(time.time() - t0, 1) * 3600
            print(f"  {min(n * 40, len(pending))}/{len(pending)} repos, {done_bytes / 1e6:.1f} MB, "
                  f"~{rate:.0f} repos/h", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
