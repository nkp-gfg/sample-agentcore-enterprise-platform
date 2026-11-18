# ═══════════════════════════════════════════════════════════════
# AgentCore Identity guardrail (org scope, SCP)
#
# Denies bedrock-agentcore:GetWorkloadAccessTokenForUserId org-wide.
#
# Why this one is worth an SCP slot: the userId path takes the user identifier as an
# unverified string. Any principal holding the action can mint a workload access token for
# any user and then read that user's credentials out of the token vault, with no JWT and no
# proof of identity anywhere in the call. Agents sitting behind Runtime or Gateway inbound
# auth never need it — the caller's verified token arrives with the request and
# GetWorkloadAccessTokenForJWT is the path that checks it.
#
# Reads the same control-library artifacts the CDK app would. With no exemption configured
# the policy is the unconditional deny, verbatim. Only an explicit, validated role ARN selects
# the exempting variant, injected with replace() rather than templatefile() so ${aws:...}
# policy variables in the body are never touched.
# ═══════════════════════════════════════════════════════════════

locals {
  identity_userid_scp_source = file(
    "${path.module}/${var.control_library_path}/scp/identity/deny-workload-token-for-userid.json"
  )

  identity_userid_scp_except_principal_source = file(
    "${path.module}/${var.control_library_path}/scp/identity/deny-workload-token-for-userid-except-principal.json"
  )

  identity_userid_scp_rendered = (
    var.identity_approved_principal_arn == ""
    ? local.identity_userid_scp_source
    : replace(
      local.identity_userid_scp_except_principal_source,
      "<<approved_principal_arn>>",
      var.identity_approved_principal_arn
    )
  )
}

# ── scp.identity.deny-workload-token-for-userid ──
# Standalone rather than merged into the consolidated gateway SCP in gateway.tf: it guards a
# different service surface (Identity, not Gateway) and toggles independently. Quota math with
# everything enabled: 1 memory + 1 consolidated gateway + 1 identity = 3 attachments per
# target, against 4 usable slots (5-per-target limit minus FullAWSAccess). A fourth standalone
# SCP is the last one that fits — merge beyond that, as gateway.tf does.
resource "aws_organizations_policy" "identity_deny_token_for_userid" {
  count = var.enable_scp_identity_deny_token_for_userid ? 1 : 0

  name        = "${var.name_prefix}-scp-identity-deny-token-for-userid"
  description = "Deny AgentCore GetWorkloadAccessTokenForUserId, which mints a token for an unverified userId."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.identity_userid_scp_rendered

  lifecycle {
    precondition {
      condition     = !strcontains(local.identity_userid_scp_rendered, "<<")
      error_message = "Unresolved <<sentinel>> in the identity SCP: every token needs a replace() above."
    }
  }
}

resource "aws_organizations_policy_attachment" "identity_deny_token_for_userid" {
  for_each = var.enable_scp_identity_deny_token_for_userid ? toset(var.target_ids) : toset([])

  policy_id = aws_organizations_policy.identity_deny_token_for_userid[0].id
  target_id = each.value
}
