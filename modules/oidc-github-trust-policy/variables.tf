variable "oidc_provider_arn" {
  description = "ARN of the account's GitHub Actions OIDC provider (token.actions.githubusercontent.com)."
  type        = string
}

variable "github_org" {
  description = "GitHub organization/owner login, e.g. \"melvyndekort\"."
  type        = string
}

variable "github_owner_id" {
  description = "Numeric GitHub owner ID, used in the immutable-subject OIDC claim (owner_id/repo_id, not names)."
  type        = number
}

variable "repo_name" {
  description = "Repository name (not used in the trust condition itself, only for documentation/outputs clarity)."
  type        = string
}

variable "repo_id" {
  description = "Numeric GitHub repo ID, used in the immutable-subject OIDC claim."
  type        = number
}

variable "create_apply_document" {
  description = "Whether to build the apply-role trust document (environment-pinned subject)."
  type        = bool
  default     = true
}

variable "environment" {
  description = "GitHub Environment the apply role's OIDC subject is pinned to."
  type        = string
  default     = "production"
}

variable "create_plan_document" {
  description = "Whether to build the read-only plan-role trust document (pull_request subject + job_workflow_ref gate)."
  type        = bool
  default     = false
}

variable "plan_job_workflow_refs" {
  description = <<-EOT
    Allowed `job_workflow_ref` claim values for the plan role, as the reusable
    workflow path plus ref (e.g.
    "melvyndekort/gha-workflows/.github/workflows/terraform-pr-plan.yml@refs/tags/v1").
    Only a job that IS the named reusable workflow presents a matching claim,
    so code authored inside a pull request can never hold the credential even
    though the caller repository and event match the subject condition.
    Required when create_plan_document is true.
  EOT
  type        = list(string)
  default     = []
}
