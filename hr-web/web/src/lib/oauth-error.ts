const OAUTH_ERROR_MESSAGES: Record<string, string> = {
  access_denied: "Sign-in was cancelled or denied by the identity provider.",
  invalid_request: "Sign-in failed due to an invalid OAuth request.",
  unauthorized_client: "This client is not authorized to sign in.",
  unsupported_response_type:
    "The identity provider does not support this sign-in flow.",
  invalid_scope: "Requested sign-in scope was rejected by the identity provider.",
  server_error: "The identity provider encountered an error. Please try again.",
  temporarily_unavailable:
    "The identity provider is temporarily unavailable. Please try again.",
  login_required: "Interactive sign-in is required. Please try signing in again.",
  interaction_required:
    "Additional verification is required by the identity provider.",
};

export function formatOAuthCallbackError(
  errorCode: string | null,
  hasErrorDescription: boolean,
): string {
  const code = String(errorCode || "").trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(OAUTH_ERROR_MESSAGES, code)) {
    return OAUTH_ERROR_MESSAGES[code] ?? "Sign-in failed. Please try signing in again.";
  }
  if (/^[a-z0-9_.-]{1,48}$/.test(code)) {
    return `Sign-in failed (${code}). Please try signing in again.`;
  }
  if (hasErrorDescription) {
    return "Sign-in was rejected by the identity provider. Please try signing in again.";
  }
  return "Sign-in failed. Please try signing in again.";
}

/**
 * Reads `?error=` for the login card and drops `code` / `state` so the
 * browser never retries an authorization code.
 */
export function takeLoginErrorFromLocation(): string {
  const params = new URLSearchParams(window.location.search);
  const oauthErr = params.get("error");
  const description = params.get("error_description");
  const hadCode = params.has("code") || params.has("state");
  if (!oauthErr && !description && !hadCode) return "";

  const url = new URL(window.location.href);
  url.searchParams.delete("error");
  url.searchParams.delete("error_description");
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  const query = url.searchParams.toString();
  window.history.replaceState(null, "", `${url.pathname}${query ? `?${query}` : ""}${url.hash}`);

  if (oauthErr || description) {
    return formatOAuthCallbackError(oauthErr, Boolean(description));
  }
  return "";
}
