"""JWT claim validation for agent identity.

Deliberately imports nothing beyond the standard library — no PyJWT, no
bedrock_agentcore — so the rules that decide whether a caller is who they claim
to be can be unit-tested anywhere (see tests/test_jwt_claims.py).

auth.py verifies the token's *signature* against the issuer's JWKS; this module
checks that the verified token is one we should accept: right issuer, one of our
clients, and an identity to act as.
"""


def gateway_token_scopes(env: dict | None = None) -> list[str]:
    """Scopes an agent requests for its Gateway M2M token.

    Empty (the Cognito default) means "whatever the client is assigned". An
    IdP issuing directly (Entra) refuses a client_credentials request with no
    scope, so app.py sets GATEWAY_TOKEN_SCOPES to the app's own `.default`.
    """
    import os

    raw = (env if env is not None else os.environ).get("GATEWAY_TOKEN_SCOPES", "")
    return [s for s in raw.split(",") if s]


def jwks_uri(issuer_url: str, discovery: dict | None = None) -> str:
    """Where the issuer publishes its signing keys.

    Cognito's is `<issuer>/.well-known/jwks.json`; Entra's is
    `.../discovery/v2.0/keys`, so the only honest source is the `jwks_uri`
    field of the OIDC discovery document. The Cognito shape is the fallback
    for callers that could not fetch discovery.
    """
    if discovery and discovery.get("jwks_uri"):
        return discovery["jwks_uri"]
    return f"{issuer_url.rstrip('/')}/.well-known/jwks.json"


class TokenRejected(ValueError):
    """The token was well-formed and signed but must not be trusted."""


def _matches_allowed_client(claims: dict, allowed_clients: tuple[str, ...]) -> bool:
    """Return True if the token's client/audience matches `allowed_clients`.

    Cognito puts the client in `aud` for user-pool ID/access tokens and in
    `client_id` for client_credentials (M2M) access tokens. When `aud` is a
    list, any matching element suffices; if there are multiple audiences, OIDC
    requires `azp` to identify an authorized party in `allowed_clients`.
    """
    audience = claims.get("aud")
    if isinstance(audience, list):
        if not any(isinstance(a, str) and a in allowed_clients for a in audience):
            return False
        if len(audience) > 1:
            azp = claims.get("azp")
            return isinstance(azp, str) and azp in allowed_clients
        return True
    if audience:
        return isinstance(audience, str) and audience in allowed_clients
    client_id = claims.get("client_id")
    return isinstance(client_id, str) and client_id in allowed_clients


def validate_claims(
    claims: dict,
    expected_issuer: str,
    allowed_clients: tuple[str, ...] = (),
    *,
    allow_any_client: bool = False,
) -> str:
    """Return the subject of an acceptable token, or raise TokenRejected.

    Non-empty `allowed_clients` is required by default so an unconfigured
    runtime fails closed; callers that intentionally trust any client from the
    issuer must pass `allow_any_client=True`.
    """
    issuer = claims.get("iss")
    if not expected_issuer:
        raise TokenRejected(
            "No expected issuer configured, so no token can be validated. Set "
            "COGNITO_ISSUER_URL on the runtime (RuntimeStack passes it when the "
            "auth stack is deployed)."
        )
    if issuer != expected_issuer:
        raise TokenRejected(f"Token issuer {issuer!r} is not {expected_issuer!r}")

    if allowed_clients:
        if not _matches_allowed_client(claims, allowed_clients):
            client_id = claims.get("aud") or claims.get("client_id")
            raise TokenRejected(
                f"Token client {client_id!r} is not one of this deployment's clients"
            )
    elif not allow_any_client:
        raise TokenRejected(
            "No allowed_clients configured; refusing to accept arbitrary clients "
            "without allow_any_client=True."
        )

    # token_use tells a Cognito access token from an ID token; both carry sub,
    # and either is fine for identifying the caller. Refresh tokens are not JWTs.
    subject = claims.get("sub")
    if not subject:
        raise TokenRejected(
            "Token has no 'sub' claim, so there is no identity to act as."
        )
    return subject
