"""Shared HTTPS and no-redirect URL helpers for agent runtimes."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP 3xx redirects so outbound bearer tokens or JWKS calls stay pinned."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP redirects are disabled for {req.full_url}",
            headers,
            fp,
        )


def no_redirect_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoRedirectHandler())


def validate_https_url(url: str, label: str = "URL") -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(f"{label} must be an https:// URL with a host, got {url!r}")
    return url
