"""Normalise AWS IAM trust-policy documents (already decoded to Python objects) into bindings."""
from __future__ import annotations

from typing import Any, Iterable

from .issuers import normalise_issuer
from .model import UNRESOLVED, Condition, Operator, Provider, TrustBinding

WEB_IDENTITY_ACTIONS = {"sts:assumerolewithwebidentity", "sts:*", "*"}


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _stringify(v: Any) -> str:
    """Render a policy scalar; anything structured (intrinsics, unresolved refs) becomes UNRESOLVED."""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float, bool)):
        return str(v).lower() if isinstance(v, bool) else str(v)
    return UNRESOLVED


def parse_operator(op: str) -> tuple[Operator, bool]:
    """Return (operator, is_negative)."""
    o = op.strip()
    vacuous = o.startswith("ForAllValues:") or o.endswith("IfExists")
    base = o.split(":", 1)[-1]
    if base.endswith("IfExists"):
        base = base[: -len("IfExists")]
    negative = base.startswith("StringNot") or base.startswith("ArnNot")
    if vacuous and not negative:
        return Operator.VACUOUS, False
    if base in ("StringEquals", "StringEqualsIgnoreCase", "ArnEquals"):
        return Operator.EQUALS, negative
    if base in ("StringLike", "ArnLike"):
        return Operator.GLOB, negative
    if base.startswith("StringNot"):
        return (Operator.GLOB if "Like" in base else Operator.EQUALS), True
    return Operator.OTHER, negative


def split_key(key: str) -> tuple[str | None, str]:
    """'token.actions.githubusercontent.com:sub' -> ('token.actions.githubusercontent.com', 'sub')."""
    if ":" not in key:
        return None, key
    host, claim = key.rsplit(":", 1)
    return normalise_issuer(host), claim


def statements_to_bindings(policy: Any, *, file: str, line: int, resource: str, iac: str,
                           via_module: str | None = None) -> list[TrustBinding]:
    if not isinstance(policy, dict):
        return []
    out: list[TrustBinding] = []
    for st in _as_list(policy.get("Statement")):
        if not isinstance(st, dict) or str(st.get("Effect", "Allow")) != "Allow":
            continue
        actions = {_stringify(a).lower() for a in _as_list(st.get("Action"))}
        if not actions & WEB_IDENTITY_ACTIONS:
            continue
        principal = st.get("Principal") or {}
        feds = _as_list(principal.get("Federated")) if isinstance(principal, dict) else []
        if not feds and "sts:assumerolewithwebidentity" not in actions:
            continue
        conditions, cond_unresolved = _conditions(st.get("Condition"))
        unresolved = cond_unresolved
        issuers = [normalise_issuer(_stringify(f)) for f in feds] or [None]
        for raw_iss in issuers:
            iss = raw_iss
            if iss is None or UNRESOLVED.lower() in iss:
                # Principal is an unresolved reference; fall back to the issuer named in condition keys.
                key_issuers = {c.key_issuer for c in conditions
                               if c.key_issuer and UNRESOLVED.lower() not in c.key_issuer}
                iss = next(iter(key_issuers)) if len(key_issuers) == 1 else iss
                unresolved = True
            out.append(TrustBinding(
                provider=Provider.AWS, file=file, line=line, resource=resource, issuer=iss,
                conditions=conditions, iac=iac, via_module=via_module, has_unresolved=unresolved,
                cond_unresolved=cond_unresolved,
            ))
    return out


def _conditions(block: Any) -> tuple[list[Condition], bool]:
    conds: list[Condition] = []
    unresolved = False
    if not isinstance(block, dict):
        return conds, block is not None
    for op_name, kv in block.items():
        op, negative = parse_operator(str(op_name))
        if negative or not isinstance(kv, dict):
            continue  # negative conditions never narrow the accepted set to a tenant
        for key, vals in kv.items():
            key_s = _stringify(key)
            host, claim = split_key(key_s)
            values = [_stringify(v) for v in _as_list(vals)]
            if any(UNRESOLVED in v for v in values) or UNRESOLVED in key_s:
                unresolved = True
            conds.append(Condition(claim=claim, operator=op, values=values, raw_key=key_s, key_issuer=host))
    return conds, unresolved


def iter_policy_documents(obj: Any) -> Iterable[dict]:
    """Yield nested dicts that look like IAM policy documents (have a Statement key)."""
    if isinstance(obj, dict):
        if "Statement" in obj:
            yield obj
        for v in obj.values():
            yield from iter_policy_documents(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_policy_documents(v)
