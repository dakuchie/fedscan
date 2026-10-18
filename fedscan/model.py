"""Core data model shared by the extractors and the rule engine.

A *trust binding* is one cloud-side statement of the form
    "tokens from issuer I whose claims satisfy C may obtain credentials for principal P".
Extractors turn IaC resources into TrustBinding objects; rules turn bindings into Findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

# Placeholder substituted for unresolved IaC expressions (Terraform ${...}, CloudFormation ${X}).
# It contains no glob metacharacters, so a pattern made of placeholders is treated as a fixed,
# unknown value (and the binding is marked has_unresolved=True).
UNRESOLVED = "⟨?⟩"


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class Operator(str, Enum):
    EQUALS = "equals"        # exact match (AWS StringEquals, Azure subject)
    GLOB = "glob"            # * and ? wildcards (AWS StringLike, Azure `matches`)
    CEL = "cel"              # GCP attribute_condition (raw CEL kept in `values[0]`)
    VACUOUS = "vacuous"      # operator that is satisfied when the key is absent (…IfExists, ForAllValues:)
    OTHER = "other"


class Severity(str, Enum):
    CRITICAL = "critical"    # cross-tenant: an outsider can mint an acceptable token
    HIGH = "high"            # tenant binding depends on attacker-controllable or unverifiable claims
    MEDIUM = "medium"        # intra-tenant over-breadth (any repo in org, any branch / PR)
    LOW = "low"              # hygiene / defence-in-depth (mutable names, missing aud)
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


@dataclass
class Condition:
    claim: str                 # normalised claim name, e.g. "sub", "aud", "repository_owner"
    operator: Operator
    values: list[str]
    raw_key: str = ""          # key as written, e.g. "token.actions.githubusercontent.com:sub"
    key_issuer: Optional[str] = None  # issuer host prefix in the key, if any (AWS)


@dataclass
class TrustBinding:
    provider: Provider
    file: str
    line: int
    resource: str                       # IaC address, e.g. aws_iam_role.deploy
    issuer: Optional[str]               # normalised issuer host+path, e.g. token.actions.githubusercontent.com
    conditions: list[Condition] = field(default_factory=list)
    iac: str = "terraform"              # terraform | cloudformation
    via_module: Optional[str] = None    # module source if derived from a community module
    has_unresolved: bool = False        # some value (principal, issuer or condition) could not be resolved
    cond_unresolved: bool = False       # specifically, the claim conditions could not be fully resolved
    # GCP only: principal patterns from IAM bindings that reference this pool (resolved per repo).
    gcp_pool: Optional[str] = None
    gcp_members: list[str] = field(default_factory=list)
    gcp_mapping: dict[str, str] = field(default_factory=dict)   # attribute.X / google.subject -> CEL

    def conds(self, claim: str) -> list[Condition]:
        return [c for c in self.conditions if c.claim == claim]


@dataclass
class Finding:
    flaw: str                 # taxonomy code, e.g. "F1"
    name: str
    severity: Severity
    message: str
    evidence: str = ""


@dataclass
class Result:
    binding: TrustBinding
    findings: list[Finding]

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict:
        d = asdict(self.binding)
        d["provider"] = self.binding.provider.value
        for c in d["conditions"]:
            c["operator"] = c["operator"].value if isinstance(c["operator"], Operator) else c["operator"]
        d["findings"] = [
            {**asdict(f), "severity": f.severity.value} for f in self.findings
        ]
        ms = self.max_severity
        d["max_severity"] = ms.value if ms else None
        from .rules import binding_scope  # local import avoids a cycle
        d["scope"] = binding_scope(self.binding)
        return d
