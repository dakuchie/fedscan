# FedScan

FedScan is a static analyzer for **OpenID Connect (OIDC) workload identity federation trust conditions** in infrastructure as code. It finds CI/CD-to-cloud trust policies that let tokens from the wrong tenant, repository, branch or pull request obtain cloud credentials.

It accompanies the article *Trusting the Pipeline: Measuring OIDC Workload Identity Federation Misconfigurations Across AWS, Azure and Google Cloud* (David Akuchie, submitted to *Computers & Security*).

## What it checks

| Cloud | Infrastructure code covered |
|---|---|
| AWS IAM | `aws_iam_role` (`jsonencode`, heredoc, `file()`), `data "aws_iam_policy_document"` (including `dynamic` conditions), `terraform-aws-modules/iam//modules/iam-github-oidc-role`, CloudFormation/SAM `AWS::IAM::Role` |
| Microsoft Entra ID | `azurerm_federated_identity_credential`, `azuread_application_federated_identity_credential`, `azuread_application_flexible_federated_identity_credential` |
| Google Cloud | `google_iam_workload_identity_pool_provider`, together with `principalSet://` IAM members and `attribute_mapping` |

Supported issuers: GitHub Actions (shared and enterprise issuers, including immutable subjects), GitLab.com, HCP Terraform, Buildkite, CircleCI and Bitbucket. Kubernetes service-account federation and Cognito are recognised and reported as out of scope.

## Install and use

```bash
pip install -e ".[dev]"
pytest                                        # 47 tests
fedscan scan path/to/repo                     # human-readable report
fedscan scan path/to/repo --format sarif      # GitHub code scanning
fedscan scan path/to/repo --fail-on high      # use as a CI gate (exit code 1)
fedscan taxonomy                              # list flaw classes
```

## Flaw taxonomy

| Code | Name | Default severity |
|---|---|---|
| T1 | Missing subject constraint | critical |
| T2 | Wildcard tenant (`repo:*`) | critical |
| T3 | Tenant-prefix confusion (`repo:acme*` also matches `acme-evil`) | critical |
| T4 | Only attacker-controlled claims constrained (branch, workflow name) | critical |
| T5 | Only `job_workflow_ref` pinned | high |
| S1 | Any repository of the owner (`repo:acme/*`) | medium |
| S2 | Any branch, environment or `pull_request` of a repository | low / medium |
| H1 | `…IfExists` / `ForAllValues` operator | low |
| H2 | No audience condition (AWS) | info |
| H3 | Tenant pinned by renameable names, or immutable-subject IDs wildcarded | low |
| H4 | Wildcard under `StringEquals` (literal, non-functional) | info |
| U | Undecidable statically (unresolved variables) | info |

Severity depends on context:
- If the issuer URL embeds the tenant (CircleCI, Bitbucket), T-class findings drop to medium.
- On Google Cloud, a T-class finding drops to low when every IAM binding on the pool pins a tenant attribute.

## Reproducing the study

The `pipeline/` folder contains the measurement pipeline:
- corpus discovery via GitHub code search or Sourcegraph
- batched IaC retrieval
- the scan
- the statistics, which produce every number and figure in the article

`data/bindings.csv` is the pseudonymised binding-level dataset. Repository identifiers are replaced by keyed hashes, and file paths, resource names and raw subject values are withheld to protect the projects studied. See `ETHICS.md` for the no-exploitation and disclosure protocol.

```bash
pip install -r pipeline/requirements.txt
python pipeline/collect.py search --out data/candidates.jsonl          # needs GITHUB_TOKEN (read-only)
python pipeline/github_fetch.py --candidates data/candidates.jsonl --dest data/gh_repos
python pipeline/collect.py scan --dest data/gh_repos --out data/scan.jsonl
python pipeline/analyze.py --scan data/scan.jsonl --meta data/gh_repos/repos.csv --out results
```

## Limitations

- FedScan is static only, and resolution is best-effort: it covers locals, tfvars and defaults, provider and pool references, module inputs and `jsonencode`.
- Protections created outside infrastructure code cannot be seen. One example is IAM bindings that application code adds at run time.
- Bicep/ARM, Pulumi and CDK source are not covered.

## Citation

See `CITATION.cff`. An archival copy of each release is deposited on Zenodo.

## License

Apache-2.0.
