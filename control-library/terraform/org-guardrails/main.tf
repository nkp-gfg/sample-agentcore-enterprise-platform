# ═══════════════════════════════════════════════════════════════
# AgentCore org-scope guardrails (SCPs)
#
# Reference apply path for org-scope Service Control Policies. Reads the SAME raw policy
# files the CDK app uses, from control-library/, and injects per-org parameters by replacing
# <<sentinel>> tokens with variable values.
#
# We use replace() rather than templatefile() on purpose: the control-library sentinel syntax
# is <<name>>, so IAM/SCP policy variables (${aws:...}) in a policy body are never touched.
# ═══════════════════════════════════════════════════════════════

locals {
  cmk_scp_source = file("${path.module}/${var.control_library_path}/scp/memory/enforce-cmk.json")

  # Left unrendered while no pattern is supplied; the precondition below refuses to create the
  # policy in that state.
  cmk_scp_rendered = var.kms_key_arn_pattern == null ? local.cmk_scp_source : replace(
    local.cmk_scp_source,
    "<<kms_key_arn_pattern>>",
    var.kms_key_arn_pattern
  )
}

# ── scp.memory.enforce-cmk ──
# Kept as its own policy (not merged into the consolidated gateway SCP in gateway.tf): it
# guards a different service surface and its enable flag toggles independently. Quota math
# with everything enabled: 1 memory SCP + 1 consolidated gateway SCP = 2 attachments per
# target, comfortably under the 5-per-target limit (4 usable after FullAWSAccess).
resource "aws_organizations_policy" "memory_enforce_cmk" {
  count = var.enable_scp_memory_enforce_cmk ? 1 : 0

  name        = "${var.name_prefix}-scp-memory-enforce-cmk"
  description = "Deny AgentCore CreateMemory unless a customer-managed KMS key is specified."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.cmk_scp_rendered

  lifecycle {
    # There is no safe default: any pattern that works without naming an account matches keys
    # outside the organization. The variable's validation rejects account wildcards.
    precondition {
      condition     = var.kms_key_arn_pattern != null
      error_message = "enable_scp_memory_enforce_cmk requires kms_key_arn_pattern naming an organization-owned key account, e.g. \"arn:aws:kms:*:111122223333:key/*\"."
    }
  }
}

resource "aws_organizations_policy_attachment" "memory_enforce_cmk" {
  for_each = var.enable_scp_memory_enforce_cmk ? toset(var.target_ids) : toset([])

  policy_id = aws_organizations_policy.memory_enforce_cmk[0].id
  target_id = each.value
}
