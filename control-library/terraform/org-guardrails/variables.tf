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
    Required. KMS key ARN pattern that AgentCore CreateMemory must reference. Must name the
    organization's key-owning account literally (no wildcard in the account field), so a
    key in an account outside the organization does not satisfy the SCP, e.g.
    "arn:aws:kms:*:111122223333:key/*" or one specific key ARN. Injected over the
    <<kms_key_arn_pattern>> sentinel in control-library/scp/memory/enforce-cmk.json.
  EOT
  type        = string
  # null rather than omitted so `terraform console` and every plan fail on the validation
  # below instead of treating the pattern as unknown.
  default = null

  validation {
    condition     = can(regex("^arn:aws(-[a-z]+)*:kms:(\\*|[a-z0-9-]+):[0-9]{12}:key/[^:]+$", var.kms_key_arn_pattern))
    error_message = "kms_key_arn_pattern is required and must pin the 12-digit account that owns the organization's key, e.g. \"arn:aws:kms:*:111122223333:key/*\". A wildcard account would accept a key from any AWS account."
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
    Required. KMS key ARN pattern a Gateway must use (bedrock-agentcore:KmsKeyArn). Must name
    the organization's key-owning account literally, e.g. "arn:aws:kms:*:111122223333:key/*".
  EOT
  type        = string
  default     = null

  validation {
    condition     = can(regex("^arn:aws(-[a-z]+)*:kms:(\\*|[a-z0-9-]+):[0-9]{12}:key/[^:]+$", var.gateway_kms_key_arn_pattern))
    error_message = "gateway_kms_key_arn_pattern is required and must pin the 12-digit account that owns the organization's key, e.g. \"arn:aws:kms:*:111122223333:key/*\". A wildcard account would accept a key from any AWS account."
  }
}

variable "approved_discovery_url_pattern" {
  description = <<-EOT
    Required. Allowed OIDC discovery URL pattern for JWT gateways
    (bedrock-agentcore:DiscoveryUrl). Must be HTTPS with a literal host and a literal first
    path segment, because hosted IdPs serve every customer's tenant from one host and anyone
    can create a tenant there. Pin the organization's tenant or user pool, e.g.
    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/*" or
    "https://login.microsoftonline.com/<tenant-id>/*".
  EOT
  type        = string
  default     = null

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]+)?/[^/*?]+(/.*)?$", var.approved_discovery_url_pattern))
    error_message = "approved_discovery_url_pattern is required and must pin the organization's IdP: https://, a literal host, and a literal first path segment (tenant or user pool), e.g. \"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/*\". A pattern such as \"https://*\" would accept an IdP anyone controls."
  }
}

variable "allowed_gateway_protocol" {
  description = "Allowed Gateway protocolType (bedrock-agentcore:ProtocolType)."
  type        = string
  default     = "MCP"
}
