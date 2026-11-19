# Shared GitHub Actions OIDC trust-policy shape, consumed by both tf-github's
# `oidc_role` module (per-workload-repo apply/plan roles) and tf-aws's
# `account-bootstrap` module (tf-github's own apply/plan roles, bootstrapped
# in tf-aws to avoid tf-github depending on a role it hasn't created yet).
#
# Before this module existed, both repos hand-built nearly identical
# `aws_iam_policy_document` blocks for this exact trust shape -- a
# security-relevant fix (e.g. the 2026-09 immutable-subject migration, or the
# 2026-10 drop of the `:ref:refs/heads/main` fallback) had to be hand-ported
# from one repo to the other. This module makes that a single edit.
#
# Deliberately out of scope: the actual `aws_iam_role` / policy-attachment /
# permissions-boundary resources, and any additional trust statements a
# caller needs beyond this shape (e.g. tf-aws's cross-account self-reference
# statement for `github-actions-tf-github`). Callers that need extra
# statements merge this module's JSON output via
# `aws_iam_policy_document.source_policy_documents`, keeping this module
# focused on the one thing that's actually duplicated.

data "aws_iam_policy_document" "apply" {
  count = var.create_apply_document ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        # Immutable-subject format (embeds owner_id/repo_id, not names),
        # pinned to a GitHub Environment rather than a branch ref -- no
        # `:ref:refs/heads/main` fallback. repo_name appears in the subject
        # string itself (GitHub's format), even though owner_id/repo_id are
        # what actually makes it immutable.
        "repo:${var.github_org}@${var.github_owner_id}/${var.repo_name}@${var.repo_id}:environment:${var.environment}",
      ]
    }
  }
}

data "aws_iam_policy_document" "plan" {
  count = var.create_plan_document ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_org}@${var.github_owner_id}/${var.repo_name}@${var.repo_id}:pull_request",
      ]
    }

    condition {
      # The apply role needs no equivalent: it's reachable only from the
      # environment gate. A PR can contain arbitrary workflow code, so this
      # pins the role to the reviewed shared plan workflow -- code authored
      # inside a pull request carries its own `job_workflow_ref`, never this
      # one, so it can never hold the credential even though the subject
      # condition above matches.
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:job_workflow_ref"
      values   = var.plan_job_workflow_refs
    }
  }
}
