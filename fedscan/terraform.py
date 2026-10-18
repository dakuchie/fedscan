"""Terraform extractor (AWS, Azure, Google Cloud).

Works on a directory (one repository / module tree). Best-effort static resolution:
  * locals and variables (from *.tfvars, then defaults) with literal string values,
  * references to aws_iam_openid_connect_provider (resource or data) -> issuer host,
  * references to google_iam_workload_identity_pool -> pool id,
  * jsonencode({...}), heredoc JSON, file()/templatefile() for IAM trust policies,
  * data "aws_iam_policy_document" blocks,
  * selected community modules (MODULES below).
Anything else becomes the UNRESOLVED placeholder and the binding is marked has_unresolved.
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator, Optional

import hcl2  # python-hcl2

from .aws_policy import parse_operator, split_key, statements_to_bindings, _as_list
from .issuers import normalise_issuer
from .model import UNRESOLVED, Condition, Operator, Provider, TrustBinding

SKIP_DIRS = {".git", ".terraform", "node_modules", "vendor"}
_TEMPLATE = re.compile(r"\{\{-?\s*(if|range|end|else|with|template|define|\.)|\{%-?\s|<%=?")


# --------------------------------------------------------------------------- string helpers
def _unquote(v: Any) -> Any:
    if isinstance(v, str) and len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1]
    return v


def _interpolations(s: str) -> Iterator[tuple[int, int, str]]:
    """Yield (start, end, inner) for each top-level ${...} in s, balancing braces and quotes."""
    i = 0
    while True:
        start = s.find("${", i)
        if start < 0:
            return
        depth, j, in_str = 0, start + 1, False
        while j < len(s):
            ch = s[j]
            if in_str:
                if ch == "\\":
                    j += 1
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield start, j + 1, s[start + 2:j]
                    break
            j += 1
        else:
            return
        i = j + 1


def _strip_heredoc(s: str) -> str:
    m = re.match(r"^<<-?\s*(\w+)\s*\n(.*)\n\s*\1\s*$", s, re.S)
    return m.group(2) if m else s


# --------------------------------------------------------------------------- module registry
# Community modules whose inputs are expanded into an equivalent trust condition.
# VERIFY against the module version pinned in each repository before relying on results.
MODULES = {
    # terraform-aws-modules/iam/aws//modules/iam-github-oidc-role : `subjects` -> repo:<subject>, StringLike
    "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role": {
        "issuer": "token.actions.githubusercontent.com",
        "input": "subjects",
        "prefix": "repo:",
        "operator": Operator.GLOB,
        "audience": "sts.amazonaws.com",
    },
}


class Repo:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self.docs: list[tuple[Path, dict]] = []
        self.parse_errors: list[tuple[str, str]] = []
        self.locals: dict[str, Any] = {}
        self.vars: dict[str, Any] = {}
        self.oidc: dict[str, str] = {}      # "aws_iam_openid_connect_provider.github" -> host
        self.pools: dict[str, str] = {}     # "google_iam_workload_identity_pool.pool" -> pool id
        self._load()

    # ----------------------------------------------------------------- loading
    def _files(self, suffix: str) -> Iterator[Path]:
        if self.root.is_file():
            if self.root.name.endswith(suffix):
                yield self.root
            return
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in filenames:
                if f.endswith(suffix):
                    yield Path(dirpath) / f

    def _load(self) -> None:
        for p in list(self._files(".tf")) + list(self._files(".tofu")):  # .tofu = OpenTofu
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                if _TEMPLATE.search(text):
                    # Go-template / Jinja sources with a .tf suffix (code generators): not Terraform.
                    self.parse_errors.append((str(p), "TEMPLATE: templated source, not Terraform"))
                    continue
                self.docs.append((p, load_hcl(text)))
            except Exception as e:  # noqa: BLE001 - parser raises many exception types
                self.parse_errors.append((str(p), f"{type(e).__name__}: {e}"[:300]))
        tfvars: dict[str, Any] = {}
        for p in self._files(".tfvars"):
            try:
                tfvars.update(load_hcl(p.read_text(encoding="utf-8", errors="replace")))
            except Exception:  # noqa: BLE001
                pass
        for _, doc in self.docs:
            for block in doc.get("locals", []):
                for k, v in block.items():
                    if not k.startswith("__"):
                        self.locals[k] = _unquote(v)
            for block in doc.get("variable", []):
                for name, body in block.items():
                    if isinstance(body, dict) and "default" in body:
                        self.vars[name] = _unquote(body["default"])
        self.vars.update({k: _unquote(v) for k, v in tfvars.items()})
        for addr, body, _ in self.blocks("resource", "aws_iam_openid_connect_provider") + \
                self.blocks("data", "aws_iam_openid_connect_provider"):
            url = body.get("url")
            if isinstance(url, str) and "${" not in url:
                self.oidc[addr] = normalise_issuer(_unquote(url)) or ""
        for addr, body, _ in self.blocks("resource", "google_iam_workload_identity_pool"):
            pid = _unquote(body.get("workload_identity_pool_id", ""))
            self.pools[addr] = pid if isinstance(pid, str) and "${" not in pid else addr.split(".")[-1]

    def blocks(self, kind: str, rtype: str) -> list[tuple[str, dict, Path]]:
        """Return (address, body, file) for every `kind "rtype" "name" {}` block."""
        out = []
        for path, doc in self.docs:
            for block in doc.get(kind, []):
                for t, named in block.items():
                    if t != rtype or not isinstance(named, dict):
                        continue
                    for name, body in named.items():
                        prefix = "data." if kind == "data" else ""
                        out.append((f"{prefix}{t}.{name}", body if isinstance(body, dict) else {}, path))
        return out

    def module_blocks(self) -> list[tuple[str, dict, Path]]:
        out = []
        for path, doc in self.docs:
            for block in doc.get("module", []):
                for name, body in block.items():
                    if isinstance(body, dict):
                        out.append((f"module.{name}", body, path))
        return out

    # ----------------------------------------------------------------- resolution
    def resolve(self, v: Any, depth: int = 0) -> Any:
        """Recursively substitute resolvable interpolations; others become UNRESOLVED."""
        if isinstance(v, list):
            return [self.resolve(x, depth) for x in v]
        if isinstance(v, dict):
            return {self.resolve(k, depth): self.resolve(x, depth) for k, x in v.items()
                    if not (isinstance(k, str) and k.startswith("__"))}
        if not isinstance(v, str):
            return v
        s = _unquote(v)
        out, last = [], 0
        for start, end, inner in _interpolations(s):
            out.append(s[last:start])
            out.append(self._expr(inner.strip(), depth))
            last = end
        out.append(s[last:])
        return "".join(out)

    def _expr(self, e: str, depth: int) -> str:
        if depth > 5:
            return UNRESOLVED
        m = re.search(r"(data\.)?aws_iam_openid_connect_provider\.([\w-]+)", e)
        if m:
            addr = f"{m.group(1) or ''}aws_iam_openid_connect_provider.{m.group(2)}"
            host = self.oidc.get(addr)
            if host:
                return f"arn:aws:iam::{UNRESOLVED}:oidc-provider/{host}" if e.endswith(".arn") else host
        m = re.search(r"google_iam_workload_identity_pool\.([\w-]+)", e)
        if m and f"google_iam_workload_identity_pool.{m.group(1)}" in self.pools:
            pid = self.pools[f"google_iam_workload_identity_pool.{m.group(1)}"]
            return f"projects/{UNRESOLVED}/locations/global/workloadIdentityPools/{pid}"
        m = re.fullmatch(r"(local|var)\.([\w-]+)", e)
        if m:
            table = self.locals if m.group(1) == "local" else self.vars
            val = table.get(m.group(2))
            # An empty default is a placeholder the user must override at deploy time: not a real value.
            if isinstance(val, str) and val != "":
                return str(self.resolve(val, depth + 1))
        return UNRESOLVED

    # ----------------------------------------------------------------- policy decoding
    def decode_policy(self, raw: Any, base: Path) -> Any:
        if isinstance(raw, dict):
            return self.resolve(raw)
        if not isinstance(raw, str):
            return None
        s = _strip_heredoc(_unquote(raw).strip())
        m = re.fullmatch(r"\$\{\s*jsonencode\((.*)\)\s*\}", s, re.S)
        if m:
            return self.resolve(_parse_hcl_object(m.group(1)))
        m = re.fullmatch(r"\$\{\s*(?:file|templatefile)\(\s*\"([^\"]+)\".*\)\s*\}", s, re.S)
        if m:
            rel = m.group(1).replace("${path.module}", ".").replace("${path.root}", ".")
            p = (base.parent / rel).resolve()
            if p.is_file():
                s = p.read_text(encoding="utf-8", errors="replace")
            else:
                return None
        if "${data.aws_iam_policy_document." in s:
            return None  # analysed separately from the data block itself
        try:
            return json.loads(str(self.resolve(s)))
        except (json.JSONDecodeError, ValueError):
            return None


_HCL_MAJOR = int(getattr(hcl2, "__version__", "4").split(".")[0] or 4)


def _normalise(v: Any) -> Any:
    """Bring python-hcl2 >= 5 output to the 4.x shape the extractors expect: strip the quotes that
    newer versions keep around string literals and block labels, drop __is_block__ markers."""
    if isinstance(v, dict):
        return {_normalise(k): _normalise(x) for k, x in v.items() if k != "__is_block__"}
    if isinstance(v, list):
        return [_normalise(x) for x in v]
    if isinstance(v, str) and len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1].replace('\\"', '"')
    return v


def _block_lines(text: str, doc: dict) -> None:
    """python-hcl2 >= 5 has no with_meta; recover block start lines by searching the source."""
    lines = text.splitlines()
    for kind in ("resource", "data", "module"):
        for block in doc.get(kind, []):
            for t, named in block.items():
                pairs = [(t, named)] if kind == "module" else \
                    [(f'{t}" "{n}', b) for n, b in named.items()] if isinstance(named, dict) else []
                for label, body in pairs:
                    if not isinstance(body, dict) or "__start_line__" in body:
                        continue
                    pat = re.compile(rf'^\s*{kind}\s+"{re.escape(label)}"')
                    body["__start_line__"] = next((i for i, l in enumerate(lines, 1) if pat.match(l)), 0)


def load_hcl(text: str) -> dict:
    if _HCL_MAJOR < 5:
        return hcl2.loads(text, with_meta=True)
    doc = _normalise(hcl2.loads(text))
    _block_lines(text, doc)
    return doc


def _parse_hcl_object(text: str) -> Any:
    # python-hcl2 4.x serialises object arguments of function calls as Python literals.
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        pass
    try:
        return _normalise(hcl2.loads(f"x = {text}\n")).get("x")
    except Exception:  # noqa: BLE001
        pass
    # Fallback: crude HCL-object -> JSON conversion.
    t = re.sub(r'(?m)(^|[{,\[\s])([A-Za-z_][\w-]*)\s*=(?!=)', r'\1"\2":', text)
    t = re.sub(r'"\s*=(?!=)\s*', '": ', t)
    t = re.sub(r'(?<![\w"$.])((?:data\.)?[a-z_]+\.[\w-]+(?:\.[\w-]+)+)(?![\w"])', r'"${\1}"', t)
    t = re.sub(r",\s*([}\]])", r"\1", t)
    try:
        return json.loads(t)
    except (json.JSONDecodeError, ValueError):
        return None


def _line(body: dict) -> int:
    return int(body.get("__start_line__", 0) or 0)


def _rel(repo: Repo, p: Path) -> str:
    try:
        return str(p.relative_to(repo.root if repo.root.is_dir() else repo.root.parent))
    except ValueError:
        return str(p)


# --------------------------------------------------------------------------- extraction
def extract(root: str | os.PathLike) -> tuple[list[TrustBinding], list[tuple[str, str]]]:
    repo = Repo(root)
    out: list[TrustBinding] = []
    out += _aws_roles(repo)
    out += _aws_policy_documents(repo)
    out += _aws_modules(repo)
    out += _gcp(repo)
    out += _azure(repo)
    return out, repo.parse_errors


def _aws_roles(repo: Repo) -> list[TrustBinding]:
    out = []
    for addr, body, path in repo.blocks("resource", "aws_iam_role"):
        raw = body.get("assume_role_policy")
        if raw is None:
            continue
        policy = repo.decode_policy(raw, path)
        if policy is None:
            continue
        out += statements_to_bindings(policy, file=_rel(repo, path), line=_line(body), resource=addr,
                                      iac="terraform")
    return out


def _aws_policy_documents(repo: Repo) -> list[TrustBinding]:
    out = []
    for addr, body, path in repo.blocks("data", "aws_iam_policy_document"):
        for st in _as_list(body.get("statement")):
            if not isinstance(st, dict):
                continue
            st = repo.resolve(st)
            if str(st.get("effect", "Allow")) != "Allow":
                continue
            actions = {str(a).lower() for a in _as_list(st.get("actions"))}
            if not actions & {"sts:assumerolewithwebidentity", "sts:*", "*"}:
                continue
            feds = []
            for pr in _as_list(st.get("principals")):
                if isinstance(pr, dict) and str(pr.get("type")) == "Federated":
                    feds += [str(i) for i in _as_list(pr.get("identifiers"))]
            conds, unresolved = [], False
            # dynamic "condition" { for_each = ...; content { test/variable/values } }: values depend on
            # the iterator, so include them as unresolved conditions (never silently drop them).
            dyn = []
            for d in _as_list(st.get("dynamic")):
                if isinstance(d, dict):
                    for label, blk in d.items():
                        if str(label).strip('"') == "condition" and isinstance(blk, dict):
                            for content in _as_list(blk.get("content")):
                                if isinstance(content, dict):
                                    dyn.append({k: (UNRESOLVED if isinstance(v, str) and "condition.value" in v
                                                    or isinstance(v, str) and "each." in v else v)
                                                for k, v in content.items()})
                                    unresolved = True
            for c in _as_list(st.get("condition")) + dyn:
                if not isinstance(c, dict):
                    continue
                op, negative = parse_operator(str(c.get("test", "")))
                if negative:
                    continue
                key = str(c.get("variable", ""))
                host, claim = split_key(key)
                if UNRESOLVED in key and c in dyn:
                    claim = "sub"  # dynamic condition on an unresolved key: assume it may pin the subject
                vals = [str(v) for v in _as_list(c.get("values"))] or [UNRESOLVED]
                unresolved |= any(UNRESOLVED in x for x in vals + [key])
                conds.append(Condition(claim=claim, operator=op, values=vals, raw_key=key, key_issuer=host))
            cond_unresolved = unresolved
            issuers = [normalise_issuer(f) for f in feds] or [None]
            for iss in issuers:
                if iss is None or UNRESOLVED in iss:
                    ks = {c.key_issuer for c in conds if c.key_issuer and UNRESOLVED not in c.key_issuer}
                    iss = next(iter(ks)) if len(ks) == 1 else iss
                    unresolved = True
                out.append(TrustBinding(provider=Provider.AWS, file=_rel(repo, path), line=_line(body),
                                        resource=addr, issuer=iss, conditions=conds, iac="terraform",
                                        has_unresolved=unresolved, cond_unresolved=cond_unresolved))
    return out


def _aws_modules(repo: Repo) -> list[TrustBinding]:
    out = []
    for addr, body, path in repo.module_blocks():
        source = str(_unquote(body.get("source", ""))).split("?")[0]
        spec = MODULES.get(source)
        if not spec:
            continue
        subjects = repo.resolve(body.get(spec["input"], []))
        subjects = subjects if isinstance(subjects, list) else [subjects]
        vals = [s if str(s).startswith(spec["prefix"]) else f"{spec['prefix']}{s}" for s in map(str, subjects)]
        iss = spec["issuer"]
        conds = [Condition("sub", spec["operator"], vals, f"{iss}:sub", iss)] if vals else []
        conds.append(Condition("aud", Operator.EQUALS, [spec["audience"]], f"{iss}:aud", iss))
        out.append(TrustBinding(provider=Provider.AWS, file=_rel(repo, path), line=_line(body), resource=addr,
                                issuer=iss, conditions=conds, iac="terraform", via_module=source,
                                has_unresolved=any(UNRESOLVED in v for v in vals),
                                cond_unresolved=any(UNRESOLVED in v for v in vals)))
    return out


def _gcp(repo: Repo) -> list[TrustBinding]:
    members: list[str] = []
    for rtype in ("google_service_account_iam_member", "google_service_account_iam_binding",
                  "google_project_iam_member", "google_project_iam_binding",
                  "google_storage_bucket_iam_member", "google_secret_manager_secret_iam_member"):
        for _, body, _ in repo.blocks("resource", rtype):
            for m in _as_list(body.get("member")) + _as_list(body.get("members")):
                m = str(repo.resolve(m))
                if "workloadIdentityPools/" in m:
                    members.append(m)
    out = []
    for addr, body, path in repo.blocks("resource", "google_iam_workload_identity_pool_provider"):
        line = _line(body)
        body = repo.resolve(body)
        oidc = (_as_list(body.get("oidc")) or [{}])[0]
        if not isinstance(oidc, dict) or not oidc:
            continue  # AWS/SAML pool providers are out of scope
        iss = normalise_issuer(str(oidc.get("issuer_uri", "")))
        cond = body.get("attribute_condition")
        if isinstance(cond, str):
            cond = _strip_heredoc(cond.strip()).strip()
        conds = [Condition("__cel__", Operator.CEL, [str(cond)])] if cond not in (None, "") else []
        mapping = body.get("attribute_mapping")
        mapping = {str(k): str(v) for k, v in mapping.items()} if isinstance(mapping, dict) else {}
        pool = str(body.get("workload_identity_pool_id", ""))
        pool_id = pool.rsplit("/", 1)[-1]
        mine = [m for m in members if f"workloadIdentityPools/{pool_id}/" in m] or \
               (members if len(repo.pools) <= 1 else [])
        out.append(TrustBinding(provider=Provider.GCP, file=_rel(repo, path), line=line, resource=addr,
                                issuer=iss, conditions=conds, iac="terraform", gcp_pool=pool_id,
                                gcp_members=mine, gcp_mapping=mapping,
                                has_unresolved=UNRESOLVED in str(cond) or UNRESOLVED in str(iss),
                                cond_unresolved=UNRESOLVED in str(cond)))
    return out


def _azure(repo: Repo) -> list[TrustBinding]:
    out = []
    for rtype in ("azurerm_federated_identity_credential", "azuread_application_federated_identity_credential",
                  "azuread_application_flexible_federated_identity_credential"):
        for addr, body, path in repo.blocks("resource", rtype):
            line = _line(body)
            body = repo.resolve(body)
            iss = normalise_issuer(str(body.get("issuer", "")))
            conds = []
            if body.get("subject") not in (None, ""):
                conds.append(Condition("sub", Operator.EQUALS, [str(body["subject"])], "subject"))
            expr = body.get("claims_matching_expression")
            if isinstance(expr, list):
                expr = (expr or [{}])[0].get("value")
            if expr:
                conds += _azure_expression(str(expr))
            auds = _as_list(body.get("audience")) + _as_list(body.get("audiences"))
            if auds:
                conds.append(Condition("aud", Operator.EQUALS, [str(a) for a in auds], "audience"))
            out.append(TrustBinding(provider=Provider.AZURE, file=_rel(repo, path), line=line,
                                    resource=addr, issuer=iss, conditions=conds, iac="terraform",
                                    has_unresolved=any(UNRESOLVED in v for c in conds for v in c.values)
                                    or UNRESOLVED in str(iss),
                                    cond_unresolved=any(UNRESOLVED in v for c in conds for v in c.values)))
    return out


def _azure_expression(expr: str) -> list[Condition]:
    """Parse Entra flexible FIC expressions such as
    claims['sub'] matches 'repo:contoso/*:ref:refs/heads/*' and claims['job_workflow_ref'] eq '...'.
    Disjunctions are kept as alternative values of the same claim (conservative: any branch admits)."""
    conds: list[Condition] = []
    disjunctive = re.search(r"\bor\b", expr, re.I) is not None
    for claim, op, val in re.findall(r"claims\[['\"]([\w.:/-]+)['\"]\]\s+(matches|eq)\s+'([^']*)'", expr):
        # equality is a glob without metacharacters, so GLOB is safe for merged alternatives
        operator = Operator.GLOB if (op == "matches" or disjunctive) else Operator.EQUALS
        same = next((c for c in conds if c.claim == claim), None) if disjunctive else None
        if same:
            same.values.append(val)
        else:
            conds.append(Condition(claim, operator, [val], f"claims['{claim}']"))
    return conds
