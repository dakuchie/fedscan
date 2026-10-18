"""Rule engine implementing the trust-condition flaw taxonomy (see TAXONOMY and paper Sect. 3).

Semantics. A binding accepts a token t iff iss(t) matches the binding issuer and every condition
holds (conditions are AND-ed; the values inside one AWS condition are OR-ed; GCP CEL may contain
explicit || and &&). We abstract each accepted *set of tokens* by a lattice element

    Constraint(tenant, project, context, pr, jwr, attacker_only)

where `tenant` says whether the tenant segment (GitHub owner, GitLab top-level group, HCP Terraform
organisation, ...) is FIXED, PREFIX (literal prefix followed by a wildcard: prefix confusion),
WILD (attacker-choosable) or NONE (not constrained at all). Conjunction takes the tightest value,
disjunction the loosest. The verdict for the binding is derived from the final element.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Iterable, Optional

from .issuers import Issuer, UNKNOWN, lookup
from .model import Condition, Finding, Operator, Provider, Result, Severity, TrustBinding

# --------------------------------------------------------------------------- taxonomy
TAXONOMY = {
    # Class T - tenant-boundary failures: tokens minted in *another* customer's tenant are accepted.
    "T1": ("Missing subject constraint", "No condition pins the issuing tenant; only the issuer is checked."),
    "T2": ("Wildcard tenant", "The tenant segment of the subject pattern is attacker-choosable."),
    "T3": ("Tenant-prefix confusion", "Tenant is matched by prefix/substring (e.g. repo:acme*), so look-alike "
           "tenants such as acme-evil match."),
    "T4": ("Attacker-controlled claim reliance", "Only claims the token holder chooses in their own tenant "
           "(branch, workflow name, environment) are constrained."),
    "T5": ("Shared reusable-workflow trust", "Only job_workflow_ref is pinned; any repository that may call "
           "that reusable workflow (any repository if it is public) obtains an acceptable token."),
    # Class S - intra-tenant scope over-breadth.
    "S1": ("Project wildcard", "Any repository/project inside the tenant is accepted."),
    "S2": ("Unrestricted execution context", "Any branch, tag, environment or pull_request run of the "
           "project is accepted, bypassing branch protection / environment approvals."),
    # Class H - hygiene / defence in depth.
    "H1": ("Non-binding operator", "…IfExists / ForAllValues operators evaluate to true when the claim "
           "is absent."),
    "H2": ("Audience unconstrained", "No audience condition (AWS also checks the provider client-ID list)."),
    "H3": ("Mutable-name binding", "Tenant is pinned by renameable names, not immutable IDs; vulnerable to "
           "namespace resurrection after rename/deletion."),
    "H4": ("Glob under exact-match operator", "Wildcard characters used with StringEquals are literal; the "
           "binding is non-functional or not what the author intended."),
    "U": ("Undecidable statically", "Tenant scoping depends on values that could not be resolved."),
}

NONE, WILD, PREFIX, FIXED = 0, 1, 2, 3   # tenant states ordered by safety


@dataclass(frozen=True)
class C:
    tenant: int = NONE
    project: bool = False
    context: bool = False
    pr: bool = False            # a pull_request context is admitted
    jwr: bool = False           # job_workflow_ref pinned
    attacker: bool = False      # some attacker-controlled claim is constrained
    has_project_dim: bool = True


TOP = C()  # accepts everything from the issuer


def conj(a: C, b: C) -> C:
    # `pr` = a pull_request context is explicitly admitted; a conjunct that fixes the context removes it.
    pr = (a.pr and not b.context) or (b.pr and not a.context)
    return C(max(a.tenant, b.tenant), a.project or b.project, a.context or b.context,
             pr, a.jwr or b.jwr, a.attacker or b.attacker, a.has_project_dim and b.has_project_dim)


def disj(a: C, b: C) -> C:
    # The loosest branch determines the tenant state, so its labelling flags (jwr/attacker) are kept.
    if a.tenant != b.tenant:
        loose = a if a.tenant < b.tenant else b
        jwr, attacker = loose.jwr, loose.attacker
    else:
        jwr, attacker = a.jwr and b.jwr, a.attacker and b.attacker
    return C(min(a.tenant, b.tenant), a.project and b.project, a.context and b.context,
             a.pr or b.pr, jwr, attacker, a.has_project_dim and b.has_project_dim)


def _all(xs: Iterable[C], op) -> C:
    xs = list(xs)
    out = xs[0]
    for x in xs[1:]:
        out = op(out, x)
    return out


def has_glob(s: Optional[str], glob: bool) -> bool:
    return bool(glob and s is not None and ("*" in s or "?" in s))


def _name_part(seg: Optional[str]) -> Optional[str]:
    """GitHub immutable subjects use NAME@ID segments ('@' cannot occur in names): the name before '@'
    identifies the tenant; a wildcard confined to the ID does not let another tenant match."""
    if seg is None or "@" not in seg:
        return seg
    return seg.split("@", 1)[0]


def _tenant_state(seg: Optional[str], glob: bool) -> int:
    seg = _name_part(seg)
    if seg is None:
        return WILD if glob else FIXED
    if not has_glob(seg, glob):
        return FIXED
    return WILD if seg[0] in "*?" else PREFIX


# --------------------------------------------------------------------------- per-value abstraction
def subject_value(issuer: Issuer, v: str, glob: bool) -> C:
    parts = issuer.parse_subject(v)
    has_project_dim = issuer.key not in ("terraform_cloud",)
    if not parts.parsed:
        if issuer.tenancy == "per_tenant" or issuer is UNKNOWN:
            # opaque grammar: treat a bare wildcard as unconstrained, anything else as fully pinned
            if glob and v.strip("*?") == "":
                return C(tenant=NONE, has_project_dim=False)
            return C(tenant=FIXED, project=True, context=not has_glob(v, glob), has_project_dim=False)
        if has_glob(v, glob) and v[0] in "*?":
            return C(tenant=WILD, has_project_dim=has_project_dim)
        return C(tenant=FIXED, project=True, context=True, has_project_dim=has_project_dim)
    tenant = _tenant_state(parts.owner, glob)
    if tenant != FIXED:
        return C(tenant=tenant, has_project_dim=has_project_dim)
    project = (parts.project is not None and not has_glob(_name_part(parts.project), glob)) or not glob
    context = (parts.context is not None and not has_glob(parts.context, glob)) or not glob
    pr = parts.context is not None and "pull_request" in parts.context
    if not has_project_dim:
        project = True
    return C(tenant=FIXED, project=project, context=context and not pr, pr=pr, has_project_dim=has_project_dim)


def claim_value(issuer: Issuer, claim: str, v: str, glob: bool) -> C:
    """Abstract a constraint on a non-`sub` claim."""
    if claim in ("sub", "google.subject"):
        return subject_value(issuer, v, glob)
    if claim in ("aud",):
        return TOP
    if claim == "job_workflow_ref":
        return C(jwr=not has_glob(v, glob))
    if claim in ("repository", "project_path"):
        owner, _, proj = v.partition("/")
        t = _tenant_state(owner, glob)
        return C(tenant=t, project=t == FIXED and bool(proj) and not has_glob(proj, glob))
    if claim in issuer.tenant_claims:
        t = _tenant_state(v, glob)
        proj = claim in ("repository_id", "project_id")
        return C(tenant=t, project=proj and t == FIXED)
    if claim in issuer.attacker_controlled_claims:
        return C(context=not has_glob(v, glob), attacker=True)
    return TOP


def condition_constraint(issuer: Issuer, c: Condition) -> C:
    glob = c.operator == Operator.GLOB
    if not c.values:
        return TOP
    # A StringLike value without metacharacters behaves exactly like StringEquals.
    return _all((claim_value(issuer, c.claim, v, glob and ("*" in v or "?" in v)) for v in c.values), disj)


# --------------------------------------------------------------------------- GCP CEL
_ATOM = re.compile(
    r"""(?:assertion|attribute)\.([\w.]+)\s*
        (?:(==)\s*(['"])(.*?)\3
          |\.(startsWith|endsWith|contains|matches)\(\s*(['"])(.*?)\6\s*\)
          |\s+in\s+\[([^\]]*)\])""", re.X)
_GOOGLE_SUBJECT = re.compile(r"google\.subject\s*==\s*(['\"])(.*?)\1")


def _split_top(expr: str, op: str) -> list[str]:
    parts, depth, cur, i = [], 0, "", 0
    while i < len(expr):
        ch = expr[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if depth == 0 and expr.startswith(op, i):
            parts.append(cur)
            cur, i = "", i + len(op)
            continue
        cur += ch
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _strip_parens(s: str) -> str:
    """Remove redundant outer parentheses: '((a && b))' -> 'a && b', but keep '(a) && (b)'."""
    s = s.strip()
    while s.startswith("("):
        depth = 0
        for i, ch in enumerate(s):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                break
        if i != len(s) - 1:
            break
        s = s[1:-1].strip()
    return s


def cel_constraint(issuer: Issuer, expr: str) -> C:
    expr = _strip_parens(expr)
    disjuncts = _split_top(expr, "||")
    if len(disjuncts) > 1:
        return _all((cel_constraint(issuer, d) for d in disjuncts), disj)
    conjuncts = _split_top(expr, "&&")
    if len(conjuncts) > 1:
        return _all((cel_constraint(issuer, d) for d in conjuncts), conj)
    atom = expr.strip()
    if atom.startswith("!") or "!=" in atom:
        return TOP  # negations never pin a tenant
    m = _GOOGLE_SUBJECT.search(atom)
    if m:
        return subject_value(issuer, m.group(2), glob=False)
    m = _ATOM.search(atom)
    if not m:
        return TOP
    claim = m.group(1)
    if m.group(2):                       # ==
        return claim_value(issuer, claim, m.group(4), glob=False)
    if m.group(5):                       # method call
        fn, v = m.group(5), m.group(7)
        pattern = {"startsWith": f"{v}*", "endsWith": f"*{v}", "contains": f"*{v}*"}.get(fn)
        if fn == "matches":
            pattern = ("" if v.startswith("^") else "*") + re.sub(r"\.\*|\.\+", "*", v.strip("^$")) + \
                      ("" if v.endswith("$") else "*")
        return claim_value(issuer, claim, pattern, glob=True)
    values = [x.strip().strip("'\"") for x in m.group(8).split(",") if x.strip()]
    if not values:
        return TOP
    return _all((claim_value(issuer, claim, v, glob=False) for v in values), disj)


# --------------------------------------------------------------------------- binding evaluation
_MAPPED_CLAIM = re.compile(r"""^\s*assertion(?:\.([\w.]+)|\[\s*['"]([^'"]+)['"]\s*\])\s*$""")


def mapped_claim(mapping: dict[str, str], attr: str) -> Optional[str]:
    """attribute_mapping {'attribute.repo': 'assertion.repository'} -> 'repository' for attr 'attribute.repo'."""
    m = _MAPPED_CLAIM.match(mapping.get(attr, ""))
    return (m.group(1) or m.group(2)) if m else None


def _apply_mapping(expr: str, mapping: dict[str, str]) -> str:
    """Rewrite attribute.X in a CEL condition to the claim it is mapped from, when the mapping is a plain
    claim reference; leaves composite mappings untouched (they are then treated as unconstrained)."""
    def sub(m: re.Match) -> str:
        claim = mapped_claim(mapping, m.group(0))
        if not claim:
            return m.group(0)
        return f"assertion.{claim}" if re.fullmatch(r"[\w.]+", claim) else f"assertion.{re.sub(r'\W', '_', claim)}"
    return re.sub(r"attribute\.[\w]+", sub, expr) if mapping else expr


def binding_constraint(b: TrustBinding, issuer: Issuer) -> C:
    parts: list[C] = []
    for c in b.conditions:
        if c.operator == Operator.CEL:
            parts.append(cel_constraint(issuer, _apply_mapping(c.values[0], b.gcp_mapping)))
        elif c.operator == Operator.VACUOUS:
            # Satisfied when the claim is absent. Claims every token carries still bind.
            if c.claim in ("sub", "aud"):
                parts.append(condition_constraint(issuer, replace(c, operator=Operator.GLOB)))
        elif c.operator in (Operator.EQUALS, Operator.GLOB):
            if b.provider == Provider.AWS and c.key_issuer and b.issuer and c.key_issuer != b.issuer:
                continue  # key of another issuer: never present in this issuer's tokens
            parts.append(condition_constraint(issuer, c))
    return _all(parts, conj) if parts else TOP


_TENANT_WORDS = ("repository", "owner", "org", "namespace", "project", "subject", "sub", "workspace")


def _gcp_members_pin_tenant(members: list[str], mapping: Optional[dict[str, str]] = None) -> Optional[bool]:
    """True: every IAM member pins a tenant attribute; False: some member is pool-wide; None: unknown.
    An attribute counts as tenant-pinning if its name, or the CEL expression it is mapped from
    (e.g. attribute.full = assertion.repository + assertion.ref), refers to a tenant-identifying claim."""
    if not members:
        return None
    mapping = mapping or {}
    pinned = True
    for m in members:
        if re.search(r"workloadIdentityPools/[^/]+/\*$", m):
            return False
        m2 = re.search(r"/(?:attribute\.([\w-]+)|subject)/(.+)$", m)
        if not m2:
            pinned = False
            continue
        attr = (m2.group(1) or "subject").lower()
        source = mapping.get(f"attribute.{m2.group(1)}", "").lower() if m2.group(1) else ""
        if not any(k in attr for k in _TENANT_WORDS) and \
                not any(f"assertion.{k}" in source or f"'{k}" in source for k in _TENANT_WORDS):
            pinned = False
    return pinned


_CI_SUBJECT = re.compile(r"^(repo:|project_path:|organization:)")
_IMMUTABLE_SUB = re.compile(r"^repo:[^/@*?]+@\d+/")       # repo:OWNER@OWNER-ID/...
_WILD_ID = re.compile(r"@[*?]")


def binding_scope(b: TrustBinding) -> str:
    """'ci' (in study scope), 'non_ci' (Kubernetes service accounts, Cognito, ...) or 'unknown'."""
    issuer = lookup(b.issuer)
    values = [v for c in b.conditions for v in c.values]
    if issuer is not UNKNOWN:
        return "ci" if issuer.ci else "non_ci"
    if any(v.startswith("system:serviceaccount:") for v in values) or \
            any(c.claim in ("amr",) or "cognito" in c.raw_key for c in b.conditions):
        return "non_ci"
    if any(_CI_SUBJECT.match(v) for v in values) or any(c.claim == "__cel__" and "assertion.repository" in v
                                                         for c in b.conditions for v in c.values):
        return "ci"
    return "unknown"


def evaluate(b: TrustBinding) -> Result:
    issuer = lookup(b.issuer)
    findings: list[Finding] = []
    k = binding_constraint(b, issuer)

    # ---- class T
    t_code = None
    if k.tenant == WILD:
        t_code = "T2"
    elif k.tenant == PREFIX:
        t_code = "T3"
    elif k.tenant == NONE:
        t_code = "T5" if k.jwr else ("T4" if k.attacker else "T1")

    if t_code:
        if b.cond_unresolved:
            findings.append(_f("U", Severity.INFO, "Tenant scoping depends on unresolved IaC values."))
        else:
            sev, note = Severity.CRITICAL, ""
            if t_code == "T5":
                sev = Severity.HIGH
            if issuer.tenancy == "per_tenant":
                sev, note = Severity.MEDIUM, " Issuer URL is tenant-scoped, so exposure is intra-tenant."
            elif issuer is UNKNOWN:
                sev, note = Severity.HIGH, " Issuer tenancy unknown (self-hosted or unrecognised)."
            if b.provider == Provider.GCP:
                pinned = _gcp_members_pin_tenant(b.gcp_members, b.gcp_mapping)
                if pinned is True:
                    sev, note = Severity.LOW, " Mitigated: all IAM principalSet bindings pin a tenant attribute."
                elif pinned is None and sev == Severity.CRITICAL:
                    sev, note = Severity.HIGH, " No IAM binding for this pool found in the repository."
            findings.append(_f(t_code, sev, TAXONOMY[t_code][1] + note))
    else:
        # ---- class S (only meaningful once the tenant boundary holds)
        if k.has_project_dim and not k.project:
            findings.append(_f("S1", Severity.MEDIUM, TAXONOMY["S1"][1]))
        elif not k.context:
            sev = Severity.MEDIUM if k.pr else Severity.LOW
            findings.append(_f("S2", sev, TAXONOMY["S2"][1] + (" (pull_request admitted)" if k.pr else "")))
        # ---- H3 mutable names (immutable claim, or GitHub immutable subject with literal numeric IDs)
        sub_values = [v for c in b.conditions if c.claim == "sub" for v in c.values]
        immutable = any(c.claim in issuer.immutable_claims or
                        any(x in c.values[0] for x in issuer.immutable_claims)
                        for c in b.conditions if c.values) or \
            (sub_values and all(_IMMUTABLE_SUB.match(v) for v in sub_values))
        if issuer.immutable_claims and not immutable:
            wild_id = [v for v in sub_values if _WILD_ID.search(v)]
            if wild_id:
                findings.append(_f("H3", Severity.LOW, TAXONOMY["H3"][1] + " Immutable-subject IDs are "
                                   "wildcarded, which negates the protection of the immutable format.",
                                   evidence=wild_id[0]))
            else:
                findings.append(_f("H3", Severity.LOW, TAXONOMY["H3"][1]))

    # ---- class H
    if any(c.operator == Operator.VACUOUS for c in b.conditions):
        findings.append(_f("H1", Severity.LOW, TAXONOMY["H1"][1]))
    if b.provider == Provider.AWS and not any(c.claim == "aud" for c in b.conditions):
        findings.append(_f("H2", Severity.INFO, TAXONOMY["H2"][1]))
    glob_eq = [v for c in b.conditions if c.operator == Operator.EQUALS for v in c.values if "*" in v]
    if glob_eq:
        findings.append(_f("H4", Severity.INFO, TAXONOMY["H4"][1], evidence=", ".join(glob_eq[:3])))
    return Result(binding=b, findings=findings)


def _f(code: str, sev: Severity, msg: str, evidence: str = "") -> Finding:
    return Finding(flaw=code, name=TAXONOMY[code][0], severity=sev, message=msg, evidence=evidence)
