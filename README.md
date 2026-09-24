# gha-workflows

Shared reusable GitHub Actions workflows for the `melvyndekort` repositories.

Every Terraform repo here used to carry its own near-identical `terraform.yml`.
Across 20 repos there were only three functional variants, so the pipeline is
defined once here and each repo keeps thin caller workflows.

## Workflows

| Workflow | Trigger in caller | Credentials |
|---|---|---|
| `terraform-pr-validate.yml` | `pull_request` | none |
| `terraform-pr-plan.yml` | `pull_request` | read-only plan role |
| `terraform-apply.yml` | `push` to `main` | apply role, environment-gated |

### terraform-pr-validate.yml

`fmt -check`, `init -backend=false`, `validate`. Requests no OIDC token and
reads no secrets, so it also runs for fork pull requests and for Dependabot —
neither of which can obtain credentials. This is the check that gives a
dependency bump real signal before auto-merge.

### terraform-pr-plan.yml

Runs `terraform plan` under a **read-only** role and posts the result as a PR
comment.

The plan role's trust policy requires two conditions: the `pull_request`
subject for the calling repository, **and** a `job_workflow_ref` matching this
file. A job only presents that claim while it *is* this reusable workflow —
steps defined in a caller repository carry the caller's own `job_workflow_ref`.
Code authored inside a pull request therefore cannot hold these credentials.

Consequence worth knowing: **anything touching AWS has to live in this file.**
Adding an AWS step to a caller workflow will not work, by design.

`-lock=false` is used because the plan role cannot write the state lock. A plan
changes no state, so racing a concurrent apply risks a stale plan, never
corruption.

The role carries `ReadOnlyAccess`, which can read secret values — including
through `terraform_remote_state` of another account's state. That is
deliberate: a plan must configure the same providers as an apply, so a
secret-read deny-list would break nearly every repo. The exposure is bounded by
restricting *which code* may assume the role. Sensitive Terraform outputs stay
redacted in plan output, so publishing the plan is safe.

### terraform-apply.yml

Applies on `main`. The apply role still carries `AdministratorAccess`, so pass
an `environment` and configure it with a deployment branch policy and a
required reviewer.

## Usage

```yaml
# .github/workflows/terraform-pr.yml
name: Terraform PR
on:
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'
      - '.github/workflows/terraform-*.yml'

jobs:
  validate:
    uses: melvyndekort/gha-workflows/.github/workflows/terraform-pr-validate.yml@v1

  plan:
    needs: validate
    uses: melvyndekort/gha-workflows/.github/workflows/terraform-pr-plan.yml@v1
    secrets:
      plan-role-arn: ${{ secrets.AWS_PLAN_ROLE_ARN }}
```

```yaml
# .github/workflows/terraform-apply.yml
name: Terraform Apply
on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'
      - '.github/workflows/terraform-*.yml'
  workflow_dispatch:

jobs:
  apply:
    uses: melvyndekort/gha-workflows/.github/workflows/terraform-apply.yml@v1
    with:
      environment: production
    secrets:
      role-arn: ${{ secrets.AWS_ROLE_ARN }}
```

Callers must not set `if: github.actor != 'dependabot[bot]'` on the validate
job — running it for Dependabot is the point.

## Prerequisites per caller repo

Both are set in `tf-github`'s `repositories.yaml`:

- `shared_workflows: true` — allow-lists this repo. GitHub's allowed-actions
  policy covers reusable workflows, so without it the call is blocked.
- `pr_plan_role: true` — creates the read-only plan role and distributes
  `AWS_PLAN_ROLE_ARN`.

## Versioning

Callers reference a tag (`@v1`), not `@main`. The IAM trust policy is the real
boundary, but a moving ref in a caller means an unreviewed change to privileged
workflow code, so tags are what callers pin to.
