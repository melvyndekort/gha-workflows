# oidc-github-trust-policy

Shared Terraform module producing the GitHub Actions OIDC trust-policy JSON
shape used across `melvyndekort`'s repos. Extracted because `tf-github`'s
`oidc_role` module and `tf-aws`'s `account-bootstrap` module independently
hand-built nearly identical `aws_iam_policy_document` blocks for this same
shape (tf-github improvement plan, Phase 2 item 1).

**Why this repo, not a dedicated tiny repo:** every repo that needs this
module (`tf-github`, `tf-aws`) already depends on `gha-workflows` for its
CI/CD reusable workflows, so this doesn't add a new repo dependency to
either consumer. A standalone repo would be marginally more "correct"
module-registry hygiene but buys nothing here, since both existing
consumers already have this dependency wired up and versioned.

## What it produces

Two independent trust-policy documents, selected by flag, matching the two
shapes used everywhere in the fleet:

- **apply** (`create_apply_document = true`, the default): OIDC federated
  `AssumeRoleWithWebIdentity`, immutable-subject (`owner_id/repo_id`, not
  names) pinned to a GitHub **Environment** (`environment:production` by
  default) -- not a branch ref.
- **plan** (`create_plan_document = true`): same federated principal, subject
  pinned to `:pull_request` instead, **plus** a `job_workflow_ref` allow-list
  condition -- this is what stops a PR's own workflow edits from holding the
  credential even though the subject condition matches.

This module only builds the trust document. Callers create their own
`aws_iam_role` / policy attachments / permissions boundaries, and merge in
any additional trust statements they need (e.g. tf-aws's cross-account
self-reference statement for `github-actions-tf-github`) via
`aws_iam_policy_document.source_policy_documents`.

## Usage

```hcl
module "trust" {
  source = "git::https://github.com/melvyndekort/gha-workflows.git//modules/oidc-github-trust-policy?ref=v2"

  oidc_provider_arn = data.aws_iam_openid_connect_provider.github.arn
  github_org        = "melvyndekort"
  github_owner_id    = 359886
  repo_name          = "tf-github"
  repo_id            = 1057394177
}

resource "aws_iam_role" "github_actions" {
  name               = "github-actions-tf-github"
  assume_role_policy = module.trust.apply_assume_role_policy_json
}
```

For the plan variant, also set `create_plan_document = true` and
`plan_job_workflow_refs`.

## Versioning

Pin `ref=` to a tagged release, same discipline as the reusable workflows in
this repo -- never `@main` from a consumer's Terraform.
