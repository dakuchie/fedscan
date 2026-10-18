"""Token-free corpus discovery via Sourcegraph's public search (the source Datadog Security Labs used in
2023). Complements collect.py, which uses GitHub code search and requires GITHUB_TOKEN.

    python sourcegraph.py count                      # repositories per query, no downloads
    python sourcegraph.py search --out data/sg_candidates.jsonl
    python sourcegraph.py fetch  --candidates data/sg_candidates.jsonl --dest data/repos

`fetch` downloads only IaC files (.tf, .tfvars, .yaml, .yml, .json, .template) from the directories
that contain a match, plus the repository root, through raw file endpoints. Downloaded files are
data: they are parsed, never executed.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import requests

SG = "https://sourcegraph.com"
QUERIES = {
    "aws_tf": "AssumeRoleWithWebIdentity lang:HCL",
    "aws_tf_module": "iam-github-oidc-role lang:HCL",
    # Sourcegraph's parser drops terms containing "AWS::"; "IAM::Role" with explicit AND works.
    "aws_cfn_yaml": "AssumeRoleWithWebIdentity AND IAM::Role lang:YAML",
    "aws_cfn_json": "AssumeRoleWithWebIdentity AWS::IAM::Role lang:JSON",
    "gcp_tf": "google_iam_workload_identity_pool_provider lang:HCL",
    "azure_tf": "federated_identity_credential lang:HCL",
}
IAC_SUFFIXES = (".tf", ".tofu", ".tfvars", ".yaml", ".yml", ".json", ".template")
UA = {"User-Agent": "oidc-trust-study (academic measurement; contact in paper)"}


def get(url: str, **kw) -> requests.Response:
    """GET with exponential backoff on 429/5xx (Sourcegraph rate-limits anonymous clients)."""
    delay = 10
    for _ in range(14):  # anonymous quota resets roughly hourly; allow waits of up to ~1.5 h in total
        r = requests.get(url, headers={**UA, **kw.pop("headers", {})}, **kw)
        if r.status_code not in (429, 500, 502, 503, 504):
            return r
        wait = int(r.headers.get("Retry-After", delay))
        print(f"HTTP {r.status_code}; backing off {wait}s", file=sys.stderr)
        time.sleep(wait)
        delay = min(delay * 2, 600)
    r.raise_for_status()
    return r


def stream(query: str) -> list[dict]:
    """Run a Sourcegraph streaming search and return the match events."""
    r = get(f"{SG}/.api/search/stream", params={"q": query},
            headers={"Accept": "text/event-stream"}, timeout=300, stream=True)
    r.raise_for_status()
    r.encoding = "utf-8"
    matches, event, data = [], None, []
    for raw in r.iter_lines(decode_unicode=True, delimiter="\n"):
        raw = raw.rstrip("\r")
        if raw == "":                      # SSE: blank line ends one event
            if event == "matches" and data:
                matches += json.loads("\n".join(data))
            elif event == "alert" and data:
                print("alert:", "\n".join(data)[:300], file=sys.stderr)
            event, data = None, []
        elif raw.startswith("event:"):
            event = raw[6:].strip()
        elif raw.startswith("data:"):
            data.append(raw[5:].lstrip(" "))
    return matches


def github_only(m: dict) -> bool:
    return m.get("repository", "").startswith("github.com/")


def cmd_count(a) -> None:
    total = set()
    for name, q in QUERIES.items():
        ms = [m for m in stream(f"{q} select:repo count:all timeout:120s") if github_only(m)]
        repos = {m["repository"] for m in ms}
        total |= repos
        print(f"{name:14} {len(repos):6} repositories")
        time.sleep(2)
    print(f"{'union':14} {len(total):6} repositories")


def cmd_search(a) -> None:
    seen = set()
    mode = "a" if a.only else "w"
    if a.only and Path(a.out).exists():
        seen = {(f"github.com/{d['repo']}", d["path"]) for d in map(json.loads, open(a.out, encoding="utf-8"))}
    with open(a.out, mode, encoding="utf-8") as out:
        for name, q in QUERIES.items():
            if a.only and name not in a.only:
                continue
            for m in stream(f"{q} type:file count:all timeout:120s"):
                if not github_only(m) or m.get("type") not in ("content", "path"):
                    continue
                key = (m["repository"], m["path"])
                if key in seen:
                    continue
                seen.add(key)
                out.write(json.dumps({"query": name, "repo": m["repository"].removeprefix("github.com/"),
                                      "path": m["path"], "commit": m.get("commit"),
                                      "stars": m.get("repoStars"), "branches": m.get("branches")}) + "\n")
            time.sleep(2)
    print(f"{len(seen)} candidate files", file=sys.stderr)


def _list_dir(repo: str, rev: str, d: str) -> list[str]:
    """List IaC files directly inside directory d via a Sourcegraph path search."""
    pat = "^" + (d.replace(".", "\\.") + "/" if d else "") + "[^/]+\\.(tf|tofu|tfvars|ya?ml|json|template)$"
    q = f"repo:^github\\.com/{repo}$@{rev} type:path file:{pat} count:200"
    return [m["path"] for m in stream(q) if m.get("type") == "path"]


MAX_ARCHIVE = 150 * 1024 * 1024


def fetch_codeload(repo: str, rev: str, dirs: set[str], target: Path) -> bool:
    """Stream the GitHub archive at `rev` and keep only IaC files inside the matched directories.
    codeload.github.com is not subject to REST-API rate limits. The archive is untrusted input:
    only regular files with IaC suffixes are written, through tarfile's 'data' filter."""
    url = f"https://codeload.github.com/{repo}/tar.gz/{rev}"
    try:
        r = requests.get(url, headers=UA, timeout=120, stream=True)
    except requests.RequestException:
        return False
    if r.status_code != 200:
        return False
    buf = io.BytesIO()
    for chunk in r.iter_content(1 << 20):
        buf.write(chunk)
        if buf.tell() > MAX_ARCHIVE:
            print(f"  {repo}: archive exceeds {MAX_ARCHIVE >> 20} MB, skipping", file=sys.stderr)
            return False
    buf.seek(0)
    target.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            keep = []
            for mem in tf.getmembers():
                parts = mem.name.split("/", 1)
                if len(parts) < 2 or not mem.isfile() or not parts[1].endswith(IAC_SUFFIXES):
                    continue
                parent = str(PurePosixPath(parts[1]).parent)
                parent = "" if parent == "." else parent
                if parent not in dirs or mem.size > 2_000_000:
                    continue
                mem.name = parts[1]
                keep.append(mem)
            tf.extractall(target, members=keep, filter="data")
    except (tarfile.TarError, OSError, EOFError) as e:
        print(f"  {repo}: archive error {e}", file=sys.stderr)
        return False
    return True


def cmd_fetch(a) -> None:
    cands: dict[str, dict] = {}
    for line in open(a.candidates, encoding="utf-8"):
        c = json.loads(line)
        e = cands.setdefault(c["repo"], {"dirs": set(), "commit": c.get("commit"), "stars": c.get("stars")})
        d = str(PurePosixPath(c["path"]).parent)
        e["dirs"].add("" if d == "." else d)
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)

    # Phase 1: parallel archive downloads from codeload (not API-rate-limited).
    todo = [(repo, e) for repo, e in sorted(cands.items())
            if e["commit"] and not (dest / repo.replace("/", "__") / ".fedscan_source").exists()]
    if a.limit:
        todo = todo[: a.limit]

    def _one(item):
        repo, e = item
        target = dest / repo.replace("/", "__")
        if fetch_codeload(repo, e["commit"], e["dirs"], target):
            (target / ".fedscan_source").write_text(json.dumps({"repo": repo, "sha": e["commit"],
                                                                "via": "sourcegraph", "fetched": "codeload"}),
                                                    encoding="utf-8")
            return True
        return False

    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for n, ok in enumerate(pool.map(_one, todo), 1):
            if n % 20 == 0 or n == len(todo):
                print(f"codeload {n}/{len(todo)}", file=sys.stderr)

    # Phase 2: anything codeload could not provide falls back to Sourcegraph raw files (rate-limited).
    meta = []
    for i, (repo, e) in enumerate(sorted(cands.items())):
        if a.limit and i >= a.limit:
            break
        target = dest / repo.replace("/", "__")
        rev = e["commit"] or "HEAD"
        if not (target / ".fedscan_source").exists() and not a.no_fallback:
            files = set()
            for d in e["dirs"]:
                files.update(_list_dir(repo, rev, d))
            for p in sorted(files):
                if not p.endswith(IAC_SUFFIXES) or ".." in p:
                    continue
                url = f"{SG}/github.com/{repo}@{rev}/-/raw/{quote(p)}"
                r = get(url, timeout=60)
                if r.status_code != 200 or len(r.content) > 2_000_000:
                    continue
                out = (target / p).resolve()
                if target.resolve() not in out.parents:
                    continue  # path traversal guard
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(r.content)
                time.sleep(1.0)  # stay under the anonymous rate limit
            target.mkdir(parents=True, exist_ok=True)
            (target / ".fedscan_source").write_text(json.dumps({"repo": repo, "sha": rev, "via": "sourcegraph"}),
                                                    encoding="utf-8")
        meta.append({"repo": repo, "head": rev, "stars": e["stars"]})
        print(f"[{i+1}/{len(cands)}] {repo}", file=sys.stderr)
    with open(dest / "repos.csv", "w", encoding="utf-8") as f:
        f.write("repo,head,stars,owner_type\n")
        for m in meta:
            f.write(f"{m['repo']},{m['head']},{m['stars'] if m['stars'] is not None else ''},\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("count")
    p = sub.add_parser("search"); p.add_argument("--out", required=True)
    p.add_argument("--only", nargs="*", help="run only these query names and append to --out")
    p = sub.add_parser("fetch"); p.add_argument("--candidates", required=True); p.add_argument("--dest", required=True)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--no-fallback", action="store_true", help="skip the rate-limited Sourcegraph raw-file fallback")
    a = ap.parse_args()
    {"count": cmd_count, "search": cmd_search, "fetch": cmd_fetch}[a.cmd](a)


if __name__ == "__main__":
    main()
