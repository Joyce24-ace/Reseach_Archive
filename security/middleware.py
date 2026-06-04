"""
Task 3 — Audit Log Middleware
Intercepts every request/response cycle to:
  - Log admin area access
  - Log HTTP 403 (permission denied)
  - Log HTTP 403 from axes (lockout) using brute-force logger
  - Log honeypot-triggered 400 responses
  - Attach request metadata to the thread-local context

This middleware is purely observational — it does NOT block requests
or modify any existing view/auth logic.
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from .audit_logger import (
    log_admin_access,
    log_permission_denied,
    log_account_lockout,
    log_honeypot_trigger,
)
from .utils import get_client_ip

audit_log = logging.getLogger("security.audit")


class AuditLogMiddleware(MiddlewareMixin):
    """
    Observational middleware that records security-relevant HTTP events.
    Placed after AuthenticationMiddleware so request.user is populated.
    """

    def process_request(self, request):
        """Attach helper data to request for downstream use."""
        request._audit_ip = get_client_ip(request)
        request._audit_ua = request.META.get("HTTP_USER_AGENT", "")
        return None  # always continue

    def process_response(self, request, response):
        """Inspect response status and emit appropriate audit events."""
        ip = getattr(request, "_audit_ip", get_client_ip(request))
        ua = getattr(request, "_audit_ua", request.META.get("HTTP_USER_AGENT", ""))
        path = request.path
        method = request.method

        user = getattr(request, "user", None)
        username = user.username if (user and user.is_authenticated) else "anonymous"
        user_id = user.id if (user and user.is_authenticated) else None

        # --- Admin access logging ---
        if path.startswith("/admin/") and response.status_code in (200, 302):
            if user and user.is_authenticated:
                log_admin_access(username, user_id, ip, path, method)

        # --- Permission denied (403) ---
        if response.status_code == 403:
            # Distinguish axes lockout (has X-Axes-Reason header) from generic 403
            if response.has_header("X-Axes-Reason") or getattr(response, "_axes_lockout", False):
                log_account_lockout(username, ip, user_agent=ua)
            else:
                log_permission_denied(username, user_id, ip, path, method, user_agent=ua)

        # --- Honeypot-triggered 400 ---
        if response.status_code == 400 and getattr(response, "_honeypot_triggered", False):
            log_honeypot_trigger(ip, path, user_agent=ua, method=method)

        return response
