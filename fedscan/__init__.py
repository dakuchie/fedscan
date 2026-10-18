"""fedscan - static analysis of OIDC workload-identity-federation trust conditions in IaC."""
from __future__ import annotations

__version__ = "0.1.0"

from .model import Result  # noqa: E402


def scan(path) -> tuple[list[Result], list[tuple[str, str]]]:
    """Extract every trust binding under `path` (Terraform + CloudFormation) and evaluate it."""
    from . import cloudformation, terraform
    from .rules import evaluate

    bindings, errors = terraform.extract(path)
    cfn, cfn_errors = cloudformation.extract(path)
    return [evaluate(b) for b in bindings + cfn], errors + cfn_errors
