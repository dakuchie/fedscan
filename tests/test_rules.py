"""Unit tests for the taxonomy rules (no parsing involved) and integration tests over fixtures."""
from pathlib import Path

import pytest

from fedscan import scan
from fedscan.model import Condition, Operator, Provider, Severity, TrustBinding
from fedscan.rules import evaluate

GH = "token.actions.githubusercontent.com"
FIX = Path(__file__).parent / "fixtures"


def aws(*conds, issuer=GH, unresolved=False):
    return TrustBinding(Provider.AWS, "f.tf", 1, "aws_iam_role.r", issuer, list(conds), cond_unresolved=unresolved)


def sub(op, *vals, issuer=GH):
    return Condition("sub", op, list(vals), f"{issuer}:sub", issuer)


AUD = Condition("aud", Operator.EQUALS, ["sts.amazonaws.com"], f"{GH}:aud", GH)


def codes(b):
    return {f.flaw: f.severity for f in evaluate(b).findings}


# ---------------------------------------------------------------- class T
def test_t1_missing_sub():
    c = codes(aws(AUD))
    assert c["T1"] == Severity.CRITICAL


@pytest.mark.parametrize("v", ["*", "repo:*", "repo:*/infra:*", "*:ref:refs/heads/main"])
def test_t2_wildcard_tenant(v):
    assert codes(aws(AUD, sub(Operator.GLOB, v)))["T2"] == Severity.CRITICAL


@pytest.mark.parametrize("v", ["repo:acme*", "repo:acme*/infra:*", "repo:ac?e/app:*"])
def test_t3_prefix_confusion(v):
    assert codes(aws(AUD, sub(Operator.GLOB, v)))["T3"] == Severity.CRITICAL


def test_one_bad_alternative_poisons_condition():
    # values inside one condition are OR-ed: a single wildcard tenant opens the role
    c = codes(aws(AUD, sub(Operator.GLOB, "repo:acme/app:ref:refs/heads/main", "repo:*")))
    assert "T2" in c


def test_and_of_conditions_tightens():
    # StringLike repo:* AND StringEquals exact -> pinned by the second condition
    b = aws(AUD, sub(Operator.GLOB, "repo:*"), sub(Operator.EQUALS, "repo:acme/app:environment:prod"))
    assert not {"T1", "T2", "T3"} & codes(b).keys()


def test_t4_attacker_controlled_claims_gcp():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH,
                     [Condition("__cel__", Operator.CEL, ["assertion.ref == 'refs/heads/main'"])],
                     gcp_members=["principalSet://iam.googleapis.com/projects/1/locations/global/"
                                  "workloadIdentityPools/pool/*"])
    assert codes(b)["T4"] == Severity.CRITICAL


def test_t5_reusable_workflow_only():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [Condition("__cel__", Operator.CEL, [
        "assertion.job_workflow_ref == 'acme/workflows/.github/workflows/deploy.yml@refs/heads/main'"])],
        gcp_members=["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"])
    assert codes(b)["T5"] == Severity.HIGH


def test_gcp_prefix_confusion_startswith():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [Condition("__cel__", Operator.CEL, [
        "assertion.repository.startsWith('acme')"])],
        gcp_members=["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"])
    assert "T3" in codes(b)


def test_gcp_owner_pinned_is_org_wide():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [Condition("__cel__", Operator.CEL, [
        "assertion.repository_owner == 'acme' && assertion.ref == 'refs/heads/main'"])])
    assert codes(b).get("S1") == Severity.MEDIUM


def test_gcp_disjunction_with_open_branch():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [Condition("__cel__", Operator.CEL, [
        "assertion.repository == 'acme/app' || assertion.ref == 'refs/heads/main'"])],
        gcp_members=["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"])
    assert "T4" in codes(b)


def test_gcp_missing_condition_mitigated_by_iam_binding():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [], gcp_members=[
        "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/"
        "attribute.repository/acme/app"])
    assert codes(b)["T1"] == Severity.LOW


def test_per_tenant_issuer_downgrades():
    b = aws(issuer="oidc.circleci.com/org/0000-1111")
    assert codes(b)["T1"] == Severity.MEDIUM


def test_unknown_issuer_credits_tenant_claims():
    # regression: CEL pinning repository_owner under an unrecognised issuer was reported as T1
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", "oidc.example.com",
                     [Condition("__cel__", Operator.CEL, ["assertion.repository_owner == 'acme'"])])
    assert not {"T1", "T2", "T3", "T4"} & codes(b).keys()


def test_immutable_subject_wildcarded_id_is_not_cross_tenant():
    # repo:OWNER@OWNER-ID/REPO@REPO-ID:... - '@' cannot occur in names, so only the ID is wildcarded
    c = codes(aws(AUD, sub(Operator.GLOB, "repo:acme@*/app@*:environment:prod")))
    assert "T3" not in c and "H3" in c


def test_immutable_subject_literal_ids_no_h3():
    c = codes(aws(AUD, sub(Operator.EQUALS, "repo:acme@123/app@456:ref:refs/heads/main")))
    assert c == {}


def test_gcp_mapped_attribute_condition_per_tenant_issuer():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", "oidc.circleci.com/org/abc",
                     [Condition("__cel__", Operator.CEL, ['attribute.project=="7bc3"'])],
                     gcp_mapping={"attribute.project": 'assertion["oidc.circleci.com/project-id"]'})
    assert not {f for f in codes(b) if f.startswith("T")}


def test_gcp_member_attribute_mapped_from_repository():
    b = TrustBinding(Provider.GCP, "f.tf", 1, "p", GH, [], gcp_members=[
        "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/attribute.full/x"],
        gcp_mapping={"attribute.full": "assertion.repository+assertion.ref"})
    assert codes(b)["T1"] == Severity.LOW


def test_unresolved_is_not_reported_as_t1():
    c = codes(aws(AUD, unresolved=True))
    assert "U" in c and "T1" not in c


# ---------------------------------------------------------------- class S / H
def test_s1_org_wide():
    assert codes(aws(AUD, sub(Operator.GLOB, "repo:acme/*")))["S1"] == Severity.MEDIUM


def test_s2_any_branch():
    assert codes(aws(AUD, sub(Operator.GLOB, "repo:acme/app:*")))["S2"] == Severity.LOW


def test_s2_pull_request():
    assert codes(aws(AUD, sub(Operator.EQUALS, "repo:acme/app:pull_request")))["S2"] == Severity.MEDIUM


def test_fully_pinned_only_hygiene():
    c = codes(aws(AUD, sub(Operator.EQUALS, "repo:acme/app:ref:refs/heads/main")))
    assert set(c) == {"H3"}


def test_h1_ifexists():
    c = codes(aws(AUD, Condition("sub", Operator.VACUOUS, ["repo:acme/app:ref:refs/heads/main"], "k", GH)))
    assert "H1" in c and "T1" not in c


def test_h2_no_audience():
    assert "H2" in codes(aws(sub(Operator.EQUALS, "repo:acme/app:ref:refs/heads/main")))


def test_h4_glob_under_equals():
    c = codes(aws(AUD, sub(Operator.EQUALS, "repo:acme/*")))
    assert "H4" in c and "T2" not in c and "S1" not in c


def test_azure_flexible_expression_wildcard_tenant():
    b = TrustBinding(Provider.AZURE, "f.tf", 1, "fic", GH,
                     [Condition("sub", Operator.GLOB, ["repo:*/app:*"], "claims['sub']")])
    assert "T2" in codes(b)


def test_gitlab_grammar():
    b = aws(Condition("sub", Operator.GLOB, ["project_path:acme/*"], "gitlab.com:sub", "gitlab.com"),
            issuer="gitlab.com")
    assert "S1" in codes(b)
    b = aws(Condition("sub", Operator.GLOB, ["project_path:*"], "gitlab.com:sub", "gitlab.com"),
            issuer="gitlab.com")
    assert "T2" in codes(b)


def test_terraform_cloud_grammar():
    b = aws(Condition("sub", Operator.GLOB, ["organization:acme:*"], "app.terraform.io:sub", "app.terraform.io"),
            issuer="app.terraform.io")
    c = codes(b)
    assert not {"T1", "T2", "T3"} & c.keys()


# ---------------------------------------------------------------- integration over fixtures
EXPECTED = {
    # (file, resource) -> expected most-severe class-T/S code (None = no T/S finding)
    ("aws_vulnerable.tf", "aws_iam_role.no_sub"): "T1",
    ("aws_vulnerable.tf", "data.aws_iam_policy_document.wild_owner"): "T2",
    ("aws_vulnerable.tf", "aws_iam_role.prefix"): "T3",
    ("aws_safe.tf", "data.aws_iam_policy_document.pinned"): None,
    ("aws_safe.tf", "aws_iam_role.org_wide"): "S1",
    ("aws_safe.tf", "module.gha_role"): "S2",
    ("gcp.tf", "google_iam_workload_identity_pool_provider.no_condition"): "T1",
    ("gcp.tf", "google_iam_workload_identity_pool_provider.repo_pinned"): None,
    ("azure.tf", "azurerm_federated_identity_credential.prod"): None,
    ("azure.tf", "azurerm_federated_identity_credential.prs"): "S2",
    ("cfn_role.yaml", "VulnerableRole"): "T1",
    ("cfn_role.yaml", "SafeRole"): None,
}
# Bindings whose verdict must be U (undecidable), not a T-class flaw.
EXPECTED_U = {("aws_dynamic.tf", "data.aws_iam_policy_document.dynamic_sub")}


@pytest.fixture(scope="module")
def fixture_results():
    results, errors = scan(FIX)
    assert not errors, errors
    out = {}
    for r in results:
        ts = [f.flaw for f in r.findings if f.flaw[0] in "TSU"]
        out[(Path(r.binding.file).name, r.binding.resource)] = ts[0] if ts else None
    return out


def test_single_terraform_file_has_no_spurious_errors():
    # regression: scanning one .tf file made the CloudFormation reader try to parse it as YAML
    results, errors = scan(FIX / "aws_vulnerable.tf")
    assert not errors and len(results) == 3


@pytest.mark.parametrize("key", sorted(EXPECTED_U))
def test_fixture_undecidable(fixture_results, key):
    assert fixture_results.get(key) == "U"


@pytest.mark.parametrize("key,code", EXPECTED.items())
def test_fixture(fixture_results, key, code):
    assert key in fixture_results, f"binding {key} not extracted; got {sorted(fixture_results)}"
    assert fixture_results[key] == code
