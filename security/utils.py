"""
Shared utilities for the security module.
"""


def get_client_ip(request) -> str:
    """
    Extract the real client IP address, respecting X-Forwarded-For
    when the application is behind a reverse proxy (Render, Nginx, etc.).
    Returns '0.0.0.0' as a safe fallback if nothing is found.
    """
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # X-Forwarded-For can be a comma-separated list; take the first entry
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")
