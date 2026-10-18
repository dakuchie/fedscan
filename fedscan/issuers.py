"""Registry of CI/CD OIDC issuers and their subject-claim grammars.

Two properties drive severity:
  * tenancy  - "shared": one issuer URL signs tokens for every customer of the platform, so a
               binding that does not pin the tenant (owner/org/group) is reachable by outsiders.
               "per_tenant": the issuer URL itself embeds the tenant (CircleCI org, Bitbucket
               workspace), so the issuer check alone already excludes other tenants.
  * owner_of - function extracting the tenant-identifying prefix from a subject pattern.

Grammars below follow each platform's public documentation; verify against current docs before
each measurement run because platforms can change claim formats (e.g. GitHub immutable subjects).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass(frozen=True)
class SubjectParts:
    owner: Optional[str]          # tenant segment (may contain glob chars); None if not parseable
    project: Optional[str]        # repo / project segment
    context: Optional[str]        # ref / environment / pull_request / run phase
    parsed: bool


def _github(sub: str) -> SubjectParts:
    # repo:<owner>/<repo>:<context>   context ∈ ref:refs/heads/x | ref:refs/tags/x | environment:x | pull_request
    # Organisations may customise the template; anything after the repo segment is treated as context.
    if not sub.startswith("repo:"):
        return SubjectParts(None, None, None, False)
    rest = sub[len("repo:"):]
    path, _, context = rest.partition(":")
    owner, sep, repo = path.partition("/")
    return SubjectParts(owner, repo if sep else None, context or None, True)


def _gitlab(sub: str) -> SubjectParts:
    # project_path:<group>[/<subgroup>...]/<project>:ref_type:<branch|tag>:ref:<name>
    m = re.match(r"^project_path:([^:]*)(?::(.*))?$", sub)
    if not m:
        return SubjectParts(None, None, None, False)
    path, context = m.group(1), m.group(2)
    owner, sep, project = path.partition("/")
    return SubjectParts(owner, project if sep else None, context, True)


def _tfc(sub: str) -> SubjectParts:
    # organization:<org>:project:<p>:workspace:<w>:run_phase:<plan|apply>
    m = re.match(r"^organization:([^:]*)(?::(.*))?$", sub)
    if not m:
        return SubjectParts(None, None, None, False)
    return SubjectParts(m.group(1), None, m.group(2), True)


def _buildkite(sub: str) -> SubjectParts:
    # organization:<org>:pipeline:<slug>:ref:<ref>:commit:<sha>:step:<key>
    m = re.match(r"^organization:([^:]*)(?::pipeline:([^:]*))?(?::(.*))?$", sub)
    if not m:
        return SubjectParts(None, None, None, False)
    return SubjectParts(m.group(1), m.group(2), m.group(3), True)


def _opaque(sub: str) -> SubjectParts:
    return SubjectParts(None, None, None, False)


@dataclass(frozen=True)
class Issuer:
    key: str
    platform: str
    tenancy: str                                  # "shared" | "per_tenant"
    match: Callable[[str], bool]
    parse_subject: Callable[[str], SubjectParts]
    # claims that pin the tenant when compared to a constant (GCP CEL, AWS custom keys, Azure expressions)
    tenant_claims: frozenset[str] = field(default_factory=frozenset)
    # claims an attacker in another tenant fully controls (names they choose in their own tenant)
    attacker_controlled_claims: frozenset[str] = field(default_factory=frozenset)
    immutable_claims: frozenset[str] = field(default_factory=frozenset)
    ci: bool = True        # False: non-CI issuer (Kubernetes service accounts, Cognito) - out of study scope


ISSUERS: list[Issuer] = [
    Issuer(
        "github", "GitHub Actions", "shared",
        lambda h: h == "token.actions.githubusercontent.com",
        _github,
        tenant_claims=frozenset({"repository_owner", "repository_owner_id", "repository", "repository_id",
                                 "enterprise", "enterprise_id", "sub"}),
        attacker_controlled_claims=frozenset({"ref", "ref_type", "workflow", "environment", "job_workflow_ref",
                                              "workflow_ref", "event_name", "base_ref", "head_ref", "actor",
                                              "runner_environment", "ref_protected"}),
        immutable_claims=frozenset({"repository_owner_id", "repository_id", "enterprise_id"}),
    ),
    Issuer(
        # GitHub Enterprise Cloud custom issuer: token.actions.githubusercontent.com/<enterprise-slug>
        "github_enterprise", "GitHub Actions (enterprise issuer)", "per_tenant",
        lambda h: h.startswith("token.actions.githubusercontent.com/"),
        _github,
        tenant_claims=frozenset({"repository_owner", "repository_owner_id", "repository", "repository_id", "sub"}),
        attacker_controlled_claims=frozenset({"ref", "workflow", "environment", "job_workflow_ref", "actor"}),
        immutable_claims=frozenset({"repository_owner_id", "repository_id"}),
    ),
    Issuer(
        "gitlab", "GitLab.com", "shared",
        lambda h: h == "gitlab.com",
        _gitlab,
        tenant_claims=frozenset({"namespace_path", "namespace_id", "project_path", "project_id", "sub"}),
        attacker_controlled_claims=frozenset({"ref", "ref_type", "environment", "pipeline_source", "user_login",
                                              "ref_protected"}),
        immutable_claims=frozenset({"namespace_id", "project_id"}),
    ),
    Issuer(
        "terraform_cloud", "HCP Terraform", "shared",
        lambda h: h == "app.terraform.io",
        _tfc,
        tenant_claims=frozenset({"terraform_organization_name", "terraform_organization_id", "sub"}),
        attacker_controlled_claims=frozenset({"terraform_workspace_name", "terraform_project_name",
                                              "terraform_run_phase"}),
        immutable_claims=frozenset({"terraform_organization_id"}),
    ),
    Issuer(
        "buildkite", "Buildkite", "shared",
        lambda h: h == "agent.buildkite.com",
        _buildkite,
        tenant_claims=frozenset({"organization_slug", "sub"}),
        attacker_controlled_claims=frozenset({"pipeline_slug", "build_branch"}),
    ),
    Issuer(
        "circleci", "CircleCI", "per_tenant",
        lambda h: h.startswith("oidc.circleci.com/org/"),
        _opaque,
        # project-id after attribute-mapping rewrite becomes oidc_circleci_com_project_id
        tenant_claims=frozenset({"sub", "oidc.circleci.com/project-id", "oidc_circleci_com_project_id",
                                 "oidc_circleci_com_vcs_origin"}),
    ),
    Issuer(
        "bitbucket", "Bitbucket Pipelines", "per_tenant",
        lambda h: h.startswith("api.bitbucket.org/2.0/workspaces/"),
        _opaque,
        tenant_claims=frozenset({"sub", "repositoryUuid", "workspaceUuid"}),
    ),
    # ---- non-CI issuers that also use AssumeRoleWithWebIdentity / federation (excluded from analysis)
    Issuer("eks", "Kubernetes (EKS IRSA)", "per_tenant",
           lambda h: bool(re.match(r"^oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/", h)), _opaque, ci=False),
    Issuer("aks", "Kubernetes (AKS)", "per_tenant",
           lambda h: ".oic.prod-aks.azure.com" in h or h.startswith("oidc.prod-aks.azure.com"), _opaque, ci=False),
    Issuer("gke", "Kubernetes (GKE)", "per_tenant",
           lambda h: h.startswith("container.googleapis.com/"), _opaque, ci=False),
    Issuer("cognito", "Amazon Cognito", "per_tenant",
           lambda h: h == "cognito-identity.amazonaws.com", _opaque, ci=False),
]

# Unknown issuers: credit any claim that pins a tenant on some known platform (conservative for T-class).
UNKNOWN = Issuer("unknown", "Unknown / self-hosted", "unknown", lambda h: True, _opaque,
                 tenant_claims=frozenset().union(*(i.tenant_claims for i in ISSUERS)),
                 attacker_controlled_claims=frozenset().union(*(i.attacker_controlled_claims for i in ISSUERS)))

_GITLAB_LIKE = re.compile(r"^(gitlab\.|git\.)")  # self-managed GitLab: treated as per-tenant


def normalise_issuer(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().strip('"')
    s = re.sub(r"^https?://", "", s)
    # IAM OIDC provider ARN: arn:aws:iam::<acct>:oidc-provider/<host/path>
    m = re.search(r"oidc-provider/(.+)$", s)
    if m:
        s = m.group(1)
    return s.rstrip("/").lower() or None


def lookup(issuer: Optional[str]) -> Issuer:
    if not issuer:
        return UNKNOWN
    for i in ISSUERS:
        if i.match(issuer):
            return i
    return UNKNOWN


def platform_of(issuer: Optional[str]) -> str:
    i = lookup(issuer)
    if i is UNKNOWN and issuer and _GITLAB_LIKE.match(issuer):
        return "GitLab (self-managed)"
    return i.platform
