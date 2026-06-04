"""
Task 2 — Honeypot signal handler.
Logs bot activity when django-honeypot detects a filled hidden field.
"""

from .audit_logger import log_honeypot_trigger
from .utils import get_client_ip


def on_honeypot_detected(sender, request, **kwargs):
    """
    Connected to honeypot.signals.honeypot_detected in SecurityConfig.ready().
    Emits a structured warning log entry.
    """
    ip = get_client_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")
    path = request.path
    method = request.method
    log_honeypot_trigger(ip=ip, path=path, user_agent=ua, method=method)
    # Flag the request so AuditLogMiddleware can annotate the response too
    request._honeypot_detected = True
