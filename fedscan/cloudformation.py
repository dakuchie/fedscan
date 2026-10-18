"""CloudFormation / SAM extractor (YAML or JSON templates) for AWS::IAM::Role trust policies."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

from .aws_policy import statements_to_bindings
from .model import UNRESOLVED, TrustBinding

SKIP_DIRS = {".git", "node_modules", "vendor", ".aws-sam"}


class _Loader(yaml.SafeLoader):
    """SafeLoader that maps CloudFormation short-form intrinsics (!Sub, !Ref, ...) to long form."""


def _intrinsic(loader: yaml.Loader, suffix: str, node: yaml.Node) -> Any:
    name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    if isinstance(node, yaml.ScalarNode):
        val: Any = loader.construct_scalar(node)
        if suffix == "GetAtt" and isinstance(val, str):
            val = val.split(".", 1)
    elif isinstance(node, yaml.SequenceNode):
        val = loader.construct_sequence(node, deep=True)
    else:
        val = loader.construct_mapping(node, deep=True)
    return {name: val}


_Loader.add_multi_constructor("!", _intrinsic)


def _line_index(text: str) -> dict[str, int]:
    """Map logical resource id -> 1-based line (best effort, for reporting only)."""
    idx = {}
    for i, l in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s{2,4}"?([A-Za-z0-9]+)"?\s*:\s*\{?\s*$', l)
        if m and m.group(1) not in idx:
            idx[m.group(1)] = i
    return idx


def resolve(v: Any, params: dict[str, str]) -> Any:
    """Flatten intrinsics to strings where possible; everything else -> UNRESOLVED."""
    if isinstance(v, list):
        return [resolve(x, params) for x in v]
    if not isinstance(v, dict):
        return v
    if len(v) == 1:
        (k, a), = v.items()
        if k == "Fn::Sub":
            tmpl, extra = (a[0], a[1] if len(a) > 1 else {}) if isinstance(a, list) else (a, {})
            if not isinstance(tmpl, str):
                return UNRESOLVED
            local = {**params, **{kk: vv for kk, vv in (extra or {}).items() if isinstance(vv, str)}}
            return re.sub(r"\$\{([^}!]+)\}", lambda m: local.get(m.group(1), UNRESOLVED), tmpl)
        if k == "Ref":
            return params.get(str(a), UNRESOLVED)
        if k == "Fn::Join" and isinstance(a, list) and len(a) == 2 and isinstance(a[1], list):
            parts = [resolve(x, params) for x in a[1]]
            return str(a[0]).join(p if isinstance(p, str) else UNRESOLVED for p in parts)
        if k.startswith("Fn::") or k == "Ref":
            return UNRESOLVED
    return {resolve(k, params) if isinstance(k, dict) else k: resolve(x, params) for k, x in v.items()}


def _load(path: Path) -> tuple[Any, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".json":
        return json.loads(text), text
    return yaml.load(text, Loader=_Loader), text  # noqa: S506 - SafeLoader subclass


def extract(root: str | os.PathLike) -> tuple[list[TrustBinding], list[tuple[str, str]]]:
    root = Path(root)
    files: list[Path] = []
    if root.is_file():
        files = [root] if root.suffix in (".yaml", ".yml", ".json", ".template") else []
    else:
        for d, dirnames, filenames in os.walk(root):
            dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
            files += [Path(d) / f for f in filenames if f.endswith((".yaml", ".yml", ".json", ".template"))]
    out: list[TrustBinding] = []
    errors: list[tuple[str, str]] = []
    for p in files:
        try:
            raw_text = p.read_text(encoding="utf-8", errors="replace")
            if "AssumeRoleWithWebIdentity" not in raw_text:
                continue  # cheap pre-filter; most YAML in a repo is not CloudFormation
            doc, text = _load(p)
        except Exception as e:  # noqa: BLE001
            errors.append((str(p), f"{type(e).__name__}: {e}"[:300]))
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
            continue
        params = {"AWS::Partition": "aws", "AWS::URLSuffix": "amazonaws.com"}
        for name, spec in (doc.get("Parameters") or {}).items():
            # empty defaults are placeholders supplied at deploy time, not real values
            if isinstance(spec, dict) and isinstance(spec.get("Default"), str) and spec["Default"] != "":
                params[name] = spec["Default"]
        lines = _line_index(text)
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        for logical, res in doc["Resources"].items():
            if not isinstance(res, dict) or res.get("Type") != "AWS::IAM::Role":
                continue
            policy = resolve((res.get("Properties") or {}).get("AssumeRolePolicyDocument"), params)
            if isinstance(policy, str):
                try:
                    policy = json.loads(policy)
                except ValueError:
                    continue
            out += statements_to_bindings(policy, file=rel, line=lines.get(logical, 0), resource=logical,
                                          iac="cloudformation")
    return out, errors
