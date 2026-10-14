######################################################################
# Pipeline identity: GitHub Actions OIDC roles (adapted from Lab 4.3)
#
# Two roles, split by when they can be assumed:
# - plan role:  pull_request runs only. Read-only + state lock file.
# - apply role: main branch only. Broad deploy permissions, with
#   explicit denies so the pipeline can't tamper with evidence
#   (Object Lock bypass, version deletes, retention changes) or
#   use the PHI key to read patient data.
#
# The GitHub OIDC provider already exists in this account (shared
# with cgep-labs), so it's referenced, not created.
######################################################################

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  gh_owner = "bfiser"
  gh_repo  = "cgep-capstone"

  state_bucket = "acme-health-intake-tfstate-${data.aws_caller_identity.current.account_id}"
}

# --- Trust policies ------------------------------------------------

data "aws_iam_policy_document" "plan_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${local.gh_owner}/${local.gh_repo}:pull_request",
        "repo:${local.gh_owner}@*/${local.gh_repo}@*:pull_request",
      ]
    }
  }
}

data "aws_iam_policy_document" "apply_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${local.gh_owner}/${local.gh_repo}:ref:refs/heads/main",
        "repo:${local.gh_owner}@*/${local.gh_repo}@*:ref:refs/heads/main",
      ]
    }
  }
}

# --- Plan role (pull requests) -------------------------------------

resource "aws_iam_role" "pipeline_plan" {
  name               = "${local.name_prefix}-pipeline-plan"
  assume_role_policy = data.aws_iam_policy_document.plan_trust.json
  tags               = { DataClass = "pipeline" }
}

resource "aws_iam_role_policy_attachment" "pipeline_plan_readonly" {
  role       = aws_iam_role.pipeline_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Plan needs to take the state lock (write/delete the .tflock file)
data "aws_iam_policy_document" "pipeline_plan_state_lock" {
  statement {
    sid       = "StateLockFile"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${local.state_bucket}/capstone/terraform.tfstate.tflock"]
  }
}

resource "aws_iam_role_policy" "pipeline_plan_state_lock" {
  name   = "state-lock"
  role   = aws_iam_role.pipeline_plan.id
  policy = data.aws_iam_policy_document.pipeline_plan_state_lock.json
}

# --- Apply role (main branch only) ---------------------------------

resource "aws_iam_role" "pipeline_apply" {
  name               = "${local.name_prefix}-pipeline-apply"
  assume_role_policy = data.aws_iam_policy_document.apply_trust.json
  tags               = { DataClass = "pipeline" }
}

resource "aws_iam_role_policy_attachment" "pipeline_apply_admin" {
  role       = aws_iam_role.pipeline_apply.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Explicit denies always win over the Allow above
data "aws_iam_policy_document" "pipeline_apply_guardrails" {
  statement {
    sid    = "NoEvidenceTampering"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention",
      "s3:DeleteObjectVersion",
      "s3:PutObjectRetention",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid    = "NoPhiKeyDataUse"
    effect = "Deny"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = [aws_kms_key.phi.arn]
  }
}

resource "aws_iam_role_policy" "pipeline_apply_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.pipeline_apply.id
  policy = data.aws_iam_policy_document.pipeline_apply_guardrails.json
}

output "pipeline_plan_role_arn" {
  value = aws_iam_role.pipeline_plan.arn
}

output "pipeline_apply_role_arn" {
  value = aws_iam_role.pipeline_apply.arn
}