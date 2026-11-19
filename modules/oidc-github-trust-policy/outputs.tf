output "apply_assume_role_policy_json" {
  description = "Trust-policy JSON for the environment-pinned apply role, or null if create_apply_document = false."
  value       = try(data.aws_iam_policy_document.apply[0].json, null)
}

output "plan_assume_role_policy_json" {
  description = "Trust-policy JSON for the pull_request + job_workflow_ref-pinned read-only plan role, or null if create_plan_document = false."
  value       = try(data.aws_iam_policy_document.plan[0].json, null)
}
