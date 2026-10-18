resource "google_iam_workload_identity_pool" "pool" {
  workload_identity_pool_id = "github"
}

# T1: no attribute_condition and a pool-wide IAM binding below.
resource "google_iam_workload_identity_pool_provider" "no_condition" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-open"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Pinned to one repository and branch.
resource "google_iam_workload_identity_pool_provider" "repo_pinned" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-pinned"
  attribute_condition                = "assertion.repository == 'acme/app' && assertion.ref == 'refs/heads/main'"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "wif" {
  service_account_id = "projects/p/serviceAccounts/deploy@p.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.pool.name}/*"
}
