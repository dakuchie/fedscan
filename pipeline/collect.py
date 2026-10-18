"""Corpus collection: find public GitHub repositories whose IaC declares OIDC trust bindings,
clone them (blobless, full history for file-age analysis) and run fedscan.

Usage:
    GITHUB_TOKEN in the environment (fine-grained, public read-only). On Windows a persistent user variable
    set with [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "...", "User") is also picked up.
    python collect.py search  --out data/candidates.jsonl
    python collect.py clone   --candidates data/candidates.jsonl --dest data/repos
    python collect.py scan    --dest data/repos --out data/scan.jsonl
(clone writes repository metadata to <dest>/repos.csv)

Ethics: public data only; no credential use or role assumption is ever attempted; owner/repo
names are pseudonymised (HMAC) in any released dataset - see ../ETHICS.md.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import requests

API = "https://api.github.com"

# Each query targets one binding type; size: shards keep every query under the 1,000-result cap.
QUERIES = {
    "aws_tf": '"AssumeRoleWithWebIdentity" language:HCL',
    "aws_tf_module": '"iam-github-oidc-role" language:HCL',
    "aws_cfn_yaml": '"AssumeRoleWithWebIdentity" "AWS::IAM::Role" language:YAML',
    "aws_cfn_json": '"AssumeRoleWithWebIdentity" "AWS::IAM::Role" language:JSON',
    "gcp_tf": '"google_iam_workload_identity_pool_provider" language:HCL',
    "azure_tf": '"federated_identity_credential" language:HCL',
}
SIZE_SHARDS = [(0, 1500), (1501, 3000), (3001, 5000), (5001, 8000), (8001, 12000),
               (12001, 20000), (20001, 40000), (40001, 400000)]


def gh(session: requests.Session, url: str, **params) -> requests.Response:
    while True:
        r = session.get(url, params=params, timeout=60)
        if r.status_code in (403, 429) and ("rate limit" in r.text.lower() or "secondary" in r.text.lower()):
            reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), int(r.headers.get("Retry-After", 30)), 10)
            print(f"rate limited; sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
        r.raise_for_status()
        return r


def github_token() -> str | None:
    """GITHUB_TOKEN from the process environment, else (Windows) from the user's persistent environment
    in HKCU\\Environment, so a token set with SetEnvironmentVariable(..., 'User') works in existing shells.
    The value is never printed or logged."""
    tok = os.environ.get("GITHUB_TOKEN")
    if tok or sys.platform != "win32":
        return tok
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, "GITHUB_TOKEN")[0] or None
    except OSError:
        return None


def session() -> requests.Session:
    tok = github_token()
    if not tok:
        sys.exit("GITHUB_TOKEN is required (set it in your own terminal; never paste it into chat)")
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json",
                      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "oidc-trust-study"})
    return s


def cmd_count(a) -> None:
    """total_count per query and size shard (one request each) to check shards stay under 1,000."""
    s = session()
    for qname, q in QUERIES.items():
        row = []
        for lo, hi in SIZE_SHARDS:
            r = gh(s, f"{API}/search/code", q=f"{q} size:{lo}..{hi}", per_page=1)
            n = r.json().get("total_count", 0)
            row.append(f"{lo}-{hi}:{n}{'!' if n >= 1000 else ''}")
            time.sleep(6.5)
        print(f"{qname:14} " + "  ".join(row), flush=True)


def _count(s, q: str, lo: int, hi: int) -> int:
    r = gh(s, f"{API}/search/code", q=f"{q} size:{lo}..{hi}", per_page=1)
    time.sleep(6.5)
    return r.json().get("total_count", 0)


def adaptive_shards(s, q: str, lo: int, hi: int, n: int | None = None) -> list[tuple[int, int, int]]:
    """Split [lo, hi] (bytes) until every shard has < 1,000 results (the search API's hard cap)."""
    n = _count(s, q, lo, hi) if n is None else n
    if n < 1000 or hi - lo < 2:
        if n >= 1000:
            print(f"  WARNING {q} size:{lo}..{hi} still {n} results (single-byte range)", file=sys.stderr)
        return [(lo, hi, n)]
    mid = (lo + hi) // 2
    return adaptive_shards(s, q, lo, mid) + adaptive_shards(s, q, mid + 1, hi)


def cmd_search(a) -> None:
    s = session()
    seen = set()
    done_queries = set()
    if a.resume and Path(a.out).exists():
        for line in open(a.out, encoding="utf-8"):
            d = json.loads(line)
            seen.add((d["repo"], d["path"]))
        if Path(a.out + ".done").exists():
            done_queries = set(Path(a.out + ".done").read_text(encoding="utf-8").split())
    with open(a.out, "a" if a.resume else "w", encoding="utf-8") as out:
        for qname, q in QUERIES.items():
            if qname in done_queries:
                continue
            shards = []
            for lo, hi in SIZE_SHARDS:
                shards += adaptive_shards(s, q, lo, hi)
            print(f"{qname}: {len(shards)} shards, {sum(x[2] for x in shards)} results", file=sys.stderr, flush=True)
            for lo, hi, n_shard in shards:
                if n_shard == 0:
                    continue
                for page in range(1, 11):  # 10 pages x 100 = 1,000 cap
                    r = gh(s, f"{API}/search/code", q=f"{q} size:{lo}..{hi}", per_page=100, page=page)
                    items = r.json().get("items", [])
                    for it in items:
                        repo = it["repository"]["full_name"]
                        key = (repo, it["path"])
                        if key in seen:
                            continue
                        seen.add(key)
                        out.write(json.dumps({"query": qname, "repo": repo, "path": it["path"],
                                              "sha": it["sha"], "fork": it["repository"]["fork"]}) + "\n")
                    out.flush()
                    time.sleep(6.5)  # code search: 10 requests/minute
                    if len(items) < 100:
                        break
            with open(a.out + ".done", "a", encoding="utf-8") as d:
                d.write(qname + "\n")      # resume skips only fully completed queries
            print(f"{qname}: done, {len(seen)} candidate files so far", file=sys.stderr, flush=True)
    print(f"{len(seen)} candidate files", file=sys.stderr)


def cmd_clone(a) -> None:
    s = session()
    repos = sorted({json.loads(l)["repo"] for l in open(a.candidates, encoding="utf-8")})
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    meta_rows = []
    for full in repos:
        try:
            m = gh(s, f"{API}/repos/{full}").json()
        except requests.HTTPError as e:
            print(f"skip {full}: {e}", file=sys.stderr)
            continue
        if m.get("fork") and not a.include_forks:
            continue
        target = dest / full.replace("/", "__")
        if shutil.which("git"):
            if not target.exists():
                subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                                f"https://github.com/{full}.git", str(target)], check=False)
                subprocess.run(["git", "-C", str(target), "checkout", "--quiet"], check=False)
            head = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True,
                                  text=True).stdout.strip()
        else:
            head = download_tarball(s, full, m.get("default_branch", "HEAD"), target)
        meta_rows.append({
            "repo": full, "head": head, "stars": m.get("stargazers_count", 0),
            "forks": m.get("forks_count", 0), "owner_type": m.get("owner", {}).get("type"),
            "created_at": m.get("created_at"), "pushed_at": m.get("pushed_at"),
            "archived": m.get("archived"), "fork": m.get("fork"), "size_kb": m.get("size"),
            "has_security_policy": None,  # filled during disclosure triage
        })
        time.sleep(0.8)
    with open(Path(a.dest) / "repos.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(meta_rows[0].keys()) if meta_rows else ["repo"])
        w.writeheader()
        w.writerows(meta_rows)


IAC_SUFFIXES = (".tf", ".tfvars", ".yaml", ".yml", ".json", ".template")


def download_tarball(s: requests.Session, full: str, ref: str, target: Path) -> str:
    """Fallback when git is unavailable: fetch the default-branch archive and keep only IaC files.
    Returns the commit SHA of the archived ref. The archive is untrusted input: members are
    extracted with tarfile's 'data' filter, and only regular files with IaC suffixes are written."""
    sha = gh(s, f"{API}/repos/{full}/commits/{ref}").json()["sha"]
    if target.exists():
        return sha
    r = gh(s, f"{API}/repos/{full}/tarball/{sha}")
    target.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tf:
        members = []
        for mem in tf.getmembers():
            parts = mem.name.split("/", 1)
            if len(parts) < 2 or not mem.isfile() or not parts[1].endswith(IAC_SUFFIXES):
                continue
            mem.name = parts[1]          # strip "<owner>-<repo>-<sha>/" prefix
            members.append(mem)
        tf.extractall(target, members=members, filter="data")
    (target / ".fedscan_source").write_text(json.dumps({"repo": full, "sha": sha}), encoding="utf-8")
    return sha


_SG_HISTORY = """query($repo: String!, $rev: String!, $path: String!, $after: String) {
  repository(name: $repo) { commit(rev: $rev) {
    ancestors(path: $path, first: 1000, after: $after) {
      nodes { author { date } } pageInfo { hasNextPage endCursor } } } } }"""


def sourcegraph_file_added(repo: str, rev: str, path: str) -> str | None:
    """Oldest commit touching `path` up to `rev`, via Sourcegraph's public GraphQL API."""
    after, oldest = None, None
    for _ in range(20):
        for attempt in range(6):
            r = requests.post("https://sourcegraph.com/.api/graphql", timeout=60,
                              headers={"User-Agent": "oidc-trust-study"},
                              json={"query": _SG_HISTORY, "variables": {"repo": f"github.com/{repo}", "rev": rev,
                                                                        "path": path, "after": after}})
            if r.status_code != 429:
                break
            time.sleep(15 * (attempt + 1))
        if r.status_code != 200:
            return oldest
        try:
            anc = r.json()["data"]["repository"]["commit"]["ancestors"]
        except (KeyError, TypeError, ValueError):
            return oldest
        if anc["nodes"]:
            oldest = anc["nodes"][-1]["author"]["date"]
        if not anc["pageInfo"]["hasNextPage"]:
            return oldest
        after = anc["pageInfo"]["endCursor"]
    return oldest


def file_added_date(repo_dir: Path, rel: str, s: requests.Session | None = None) -> str | None:
    if not (repo_dir / ".git").exists():
        src = json.loads((repo_dir / ".fedscan_source").read_text(encoding="utf-8"))
        if src.get("via") == "sourcegraph":
            return sourcegraph_file_added(src["repo"], src["sha"], rel.replace("\\", "/"))
        # Archive mode: oldest commit touching the path via the REST API (renames are not followed).
        if s is None:
            return None
        full = src["repo"]
        url = f"{API}/repos/{full}/commits"
        first = gh(s, url, path=rel.replace("\\", "/"), per_page=1)
        last = first.links.get("last", {}).get("url")
        page = gh(s, last).json() if last else first.json()
        return page[-1]["commit"]["author"]["date"] if page else None
    r = subprocess.run(["git", "-C", str(repo_dir), "log", "--diff-filter=A", "--follow", "--format=%aI",
                        "--", rel], capture_output=True, text=True)
    lines = r.stdout.strip().splitlines()
    return lines[-1] if lines else None


def pseudonym(name: str) -> str:
    key = os.environ.get("PSEUDONYM_KEY", "").encode()
    if not key:
        return name
    return hmac.new(key, name.encode(), hashlib.sha256).hexdigest()[:16]


_EXAMPLE_TOKENS = ("example", "test", "fixture", "sample", "demo", "docs/", "docs\\",
                   # deliberately vulnerable training material (CTFs, attack-path labs)
                   "challenge", "scenarios", "vulnerable", "misconfiguration", "ctf/", "ctf\\")
# Repository names that mark the whole repository as non-production: tutorials, and the test corpora
# of static-analysis rule sets (which contain intentionally insecure IaC).
_EXAMPLE_REPO_TOKENS = ("sample", "example", "demo", "tutorial", "workshop", "semgrep-rules", "checkov",
                        "kics", "tfsec", "trivy", "terrascan", "goat", "vulnerable")


def is_example_path(path: str, repo: str = "") -> bool:
    p = path.lower()
    name = repo.lower().split("/")[-1]
    return any(t in p for t in _EXAMPLE_TOKENS) or any(t in name for t in _EXAMPLE_REPO_TOKENS)


def cmd_scan(a) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))
    from fedscan import scan  # noqa: E402

    dest = Path(a.dest)
    n_err = 0
    # Archive mode needs the API to date files; without a token, dates come from Sourcegraph (if fetched
    # that way) or are left empty.
    s = session() if not shutil.which("git") and github_token() else None
    with open(a.out, "w", encoding="utf-8") as out, open(a.out + ".errors", "w", encoding="utf-8") as errf:
        for repo_dir in sorted(p for p in dest.iterdir() if p.is_dir()):
            full = repo_dir.name.replace("__", "/", 1)
            try:
                results, errors = scan(repo_dir)
            except Exception as e:  # noqa: BLE001
                errf.write(json.dumps({"repo": full, "fatal": repr(e)[:300]}) + "\n")
                continue
            for path, err in errors:
                n_err += 1
                errf.write(json.dumps({"repo": full, "file": path, "error": err}) + "\n")
            dates: dict[str, str | None] = {}
            src_file = repo_dir / ".fedscan_source"
            head = json.loads(src_file.read_text(encoding="utf-8")).get("sha") if src_file.exists() else None
            for r in results:
                d = r.to_dict()
                d["repo"] = full  # internal; pseudonymise with release step before sharing
                d["head"] = head
                f = r.binding.file
                want = a.dates == "all" or (a.dates == "aws" and d["provider"] == "aws" and d["scope"] == "ci")
                if want and f not in dates:
                    dates[f] = file_added_date(repo_dir, f, s)
                d["file_added"] = dates.get(f)
                d["path_is_example"] = is_example_path(f, full)
                out.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(f"scan complete; {n_err} parse errors logged", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("count")
    p = sub.add_parser("search"); p.add_argument("--out", required=True)
    p.add_argument("--resume", action="store_true", help="append, skipping queries already completed")
    p = sub.add_parser("clone"); p.add_argument("--candidates", required=True); p.add_argument("--dest", required=True)
    p.add_argument("--include-forks", action="store_true")
    p = sub.add_parser("scan"); p.add_argument("--dest", required=True); p.add_argument("--out", required=True)
    p.add_argument("--dates", choices=["none", "aws", "all"], default="aws",
                   help="which bindings to date (file-added commit); dating is rate-limited and slow")
    a = ap.parse_args()
    {"count": cmd_count, "search": cmd_search, "clone": cmd_clone, "scan": cmd_scan}[a.cmd](a)


if __name__ == "__main__":
    main()
