locals {
  org = "acme"
}

# Fully pinned: repository + branch, audience checked.
data "aws_iam_policy_document" "pinned" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:acme/app:ref:refs/heads/main"]
    }
  }
}

# S1: tenant pinned (via a local), but any repository in the organisation is accepted.
resource "aws_iam_role" "org_wide" {
  name = "org-wide"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${local.org}/*" }
      }
    }]
  })
}

# S2 via community module: repository pinned, any ref.
module "gha_role" {
  source   = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"
  subjects = ["acme/app:*"]
}
