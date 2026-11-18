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
    KMS key ARN pattern that AgentCore CreateMemory must reference. Default requires any CMK.
    Narrow to a specific key/OU-owned key ARN pattern to restrict further. Injected over the
    <<kms_key_arn_pattern>> sentinel in control-library/scp/memory/enforce-cmk.json.
  EOT
  type        = string
  default     = "arn:aws:kms:*:*:key/*"
}

# ── Control: scp.identity.deny-workload-token-for-userid ──
variable "enable_scp_identity_deny_token_for_userid" {
  description = "Create and attach the 'deny GetWorkloadAccessTokenForUserId' SCP."
  type        = bool
  default     = true
}

variable "identity_approved_principal_arn" {
  description = <<-EOT
    Exact IAM role ARN exempted from the GetWorkloadAccessTokenForUserId deny. Empty (the
    default) exempts nobody: the SCP is an unconditional deny. Set it only if a migration or
    batch job genuinely needs the userId path, and only to one existing role in one specific
    account whose administrators are already trusted with every user's vault credentials —
    any administrator of that account can create or re-trust a role with this ARN. Matched
    with StringNotEquals, so wildcards are not patterns. Injected over the
    <<approved_principal_arn>> sentinel in
    control-library/scp/identity/deny-workload-token-for-userid-except-principal.json.
  EOT
  type        = string
  default     = ""

  validation {
    condition = var.identity_approved_principal_arn == "" || (
      can(regex("^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/([A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64}$", var.identity_approved_principal_arn))
      && !strcontains(var.identity_approved_principal_arn, "__no_principal_may_mint_tokens_by_userid__")
    )
    error_message = "identity_approved_principal_arn must be empty or one exact IAM role ARN (arn:aws:iam::<12-digit account>:role/<name>) with no wildcards, naming a role you have created. A placeholder role name is not an exemption of nobody: any account administrator can create it."
  }
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
  description = "KMS key ARN pattern a Gateway must use (bedrock-agentcore:KmsKeyArn)."
  type        = string
  default     = "arn:aws:kms:*:*:key/*"
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
