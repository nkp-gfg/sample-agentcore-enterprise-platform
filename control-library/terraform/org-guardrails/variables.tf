variable "name_prefix" {
  description = "Prefix for created SCP names."
  type        = string
  default     = "agentcore"
}

variable "control_library_path" {
  description = <<-EOT
    Path to the control-library/ root, relative to this module. Both this Terraform module
    and the CDK app read the same raw policy files from there (single source of truth).
  EOT
  type        = string
  default     = "../.."
}

variable "target_ids" {
  description = <<-EOT
    Organizations root, OU, or account IDs to attach the SCPs to. SCPs are additive-deny and
    apply on top of the existing FullAWSAccess policy, so attaching is non-destructive.
    Example: ["ou-abcd-1234wxyz"] or ["r-abcd"].
  EOT
  type        = list(string)

  validation {
    condition = alltrue([
      for id in var.target_ids :
      can(regex("^(r-[a-z0-9]{4,32}|ou-[a-z0-9]+-[a-z0-9]+|[0-9]{12})$", id))
    ])
    error_message = "Each target_ids entry must be an Organizations root ID (r-xxxx), an OU ID (ou-xxxx-xxxxxxxx), or a 12-digit account ID. Check for typos — an invalid ID would otherwise surface as a confusing Organizations API error at apply time."
  }
}

# ── Control: scp.memory.enforce-cmk ──
variable "enable_scp_memory_enforce_cmk" {
  description = <<-EOT
    Create and attach the 'deny CreateMemory without a CMK' SCP. Opt-in because the
    accelerator's own default deployment creates Memory without a CMK — attaching this over
    it denies the platform's own memory stack. Enable the security stack's KMS
    (enable_security) on every covered account's memory first.
  EOT
  type        = bool
  default     = false
}

variable "kms_key_arn_pattern" {
  description = <<-EOT
    KMS key ARN pattern that AgentCore CreateMemory must reference. Required when
    enable_scp_memory_enforce_cmk is true. The account field must be the literal 12-digit ID
    of an account your organization owns (for example a central key account), e.g.
    "arn:aws:kms:*:111122223333:key/*". Wildcards in the account field are rejected: they
    match keys in accounts outside the organization. Injected over the
    <<kms_key_arn_pattern>> sentinel in control-library/scp/memory/enforce-cmk.json.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn_pattern == null || can(regex("^arn:aws(-[a-z]+)*:kms:(\\*|[a-z0-9-]+):[0-9]{12}:key/([A-Za-z0-9-]+|[A-Za-z0-9-]*\\*)$", var.kms_key_arn_pattern))
    error_message = "kms_key_arn_pattern must name one organization-owned account: arn:<partition>:kms:<region or *>:<12-digit account ID>:key/<key ID, key ID prefix followed by *, or *>. Wildcards or ? in the account field match keys in any account."
  }
}

# ── Control: scp.identity.deny-workload-token-for-userid ──
variable "enable_scp_identity_deny_token_for_userid" {
  description = "Create and attach the 'deny GetWorkloadAccessTokenForUserId' SCP."
  type        = bool
  default     = true
}

variable "identity_approved_principal_arn_pattern" {
  description = <<-EOT
    Principal ARN pattern exempted from the GetWorkloadAccessTokenForUserId deny
    (aws:PrincipalArn, ArnNotLike). The default names a role that does not exist, so the
    control is a blanket deny until a real pattern is supplied. Narrow to a specific
    break-glass role ARN only if a migration or batch job genuinely needs the userId path.
    Injected over the <<approved_principal_arn_pattern>> sentinel in
    control-library/scp/identity/deny-workload-token-for-userid.json.
  EOT
  type        = string
  default     = "arn:aws:iam::*:role/__no_principal_may_mint_tokens_by_userid__"
}

# ── Controls: Gateway configuration SCPs (control plane) ──
variable "enable_gateway_scps" {
  description = <<-EOT
    Create and attach the AgentCore Gateway configuration hardening SCPs. Opt-in because
    they deny gateway settings the accelerator's default deployment uses: no gateway CMK,
    and Cedar in LOG_ONLY where the require-policy-engine SCP assumes ENFORCE. Set a
    gateway KMS key and cedar_mode=ENFORCE first, or these guardrails deny the platform's
    own gateway stack.
  EOT
  type        = bool
  default     = false
}

variable "gateway_kms_key_arn_pattern" {
  description = <<-EOT
    KMS key ARN pattern a Gateway must use (bedrock-agentcore:KmsKeyArn). Required when
    enable_gateway_scps is true. Same shape as kms_key_arn_pattern: the account field must be
    the literal 12-digit ID of an organization-owned account, e.g.
    "arn:aws:kms:*:111122223333:key/*".
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.gateway_kms_key_arn_pattern == null || can(regex("^arn:aws(-[a-z]+)*:kms:(\\*|[a-z0-9-]+):[0-9]{12}:key/([A-Za-z0-9-]+|[A-Za-z0-9-]*\\*)$", var.gateway_kms_key_arn_pattern))
    error_message = "gateway_kms_key_arn_pattern must name one organization-owned account: arn:<partition>:kms:<region or *>:<12-digit account ID>:key/<key ID, key ID prefix followed by *, or *>. Wildcards or ? in the account field match keys in any account."
  }
}

variable "approved_discovery_url_pattern" {
  description = <<-EOT
    Allowed OIDC discovery URL pattern for JWT gateways (bedrock-agentcore:DiscoveryUrl).
    Default only requires HTTPS; narrow to your IdP, e.g.
    "https://login.microsoftonline.com/<tenant>/*".
  EOT
  type        = string
  default     = "https://*"
}

variable "allowed_gateway_protocol" {
  description = "Allowed Gateway protocolType (bedrock-agentcore:ProtocolType)."
  type        = string
  default     = "MCP"
}
