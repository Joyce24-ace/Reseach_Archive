"""
Task 3 — Audit Logger
Central helper used by signals and middleware to emit structured audit events.
All events are written to the 'security.audit' logger, which is routed to
logs/audit.log via the RotatingFileHandler configured in settings.py.
"""

import logging
import uuid

audit_log = logging.getLogger("security.audit")
brute_log = logging.getLogger("security.brute_force")
honeypot_log = logging.getLogger("security.honeypot")


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _emit(logger: logging.Logger, level: int, event_type: str,
          event_category: str, message: str, **kwargs) -> None:
    """
    Emit a structured log record.
    The event_type is embedded in the message string so assertLogs() can
    match it in tests (assertLogs captures the raw msg, not formatted JSON).
    """
    extra = {
        "event_type": event_type,
        "event_category": event_category,
        "event_id": str(uuid.uuid4()),
        **kwargs,
    }
    # Prefix message with event_type so assertLogs() can find it
    full_message = f"[{event_type}] {message}"
    logger.log(level, full_message, extra=extra)


# ---------------------------------------------------------------------------
# Authentication events
# ---------------------------------------------------------------------------

def log_login_success(username: str, user_id: int, ip: str,
                      user_agent: str = None, path: str = None) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="login_success",
        event_category="authentication",
        message=f"Successful login for user '{username}'",
        username=username, user_id=user_id,
        ip_address=ip, user_agent=user_agent, request_path=path,
        http_method="POST",
    )


def log_login_failure(username: str, ip: str,
                      user_agent: str = None, path: str = None) -> None:
    _emit(
        audit_log, logging.WARNING,
        event_type="login_failure",
        event_category="authentication",
        message=f"Failed login attempt for username '{username}'",
        username=username,
        ip_address=ip, user_agent=user_agent, request_path=path,
        http_method="POST",
    )


def log_logout(username: str, user_id: int, ip: str,
               user_agent: str = None) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="logout",
        event_category="authentication",
        message=f"User '{username}' logged out",
        username=username, user_id=user_id,
        ip_address=ip, user_agent=user_agent,
    )


def log_password_reset(username: str, ip: str) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="password_reset",
        event_category="authentication",
        message=f"Password reset requested for '{username}'",
        username=username, ip_address=ip,
    )


# ---------------------------------------------------------------------------
# Authorization events
# ---------------------------------------------------------------------------

def log_permission_denied(username: str, user_id: int, ip: str,
                           path: str, method: str,
                           user_agent: str = None) -> None:
    _emit(
        audit_log, logging.WARNING,
        event_type="permission_denied",
        event_category="authorization",
        message=f"Permission denied for '{username}' on {method} {path}",
        username=username, user_id=user_id,
        ip_address=ip, request_path=path, http_method=method,
        user_agent=user_agent,
    )


def log_privilege_escalation_attempt(username: str, user_id: int,
                                      ip: str, path: str) -> None:
    _emit(
        audit_log, logging.CRITICAL,
        event_type="privilege_escalation_attempt",
        event_category="authorization",
        message=f"Privilege escalation attempt by '{username}' at {path}",
        username=username, user_id=user_id,
        ip_address=ip, request_path=path,
    )


def log_document_download(username: str, user_id: int, publication_id: int,
                        title: str, ip: str = None) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="document_download",
        event_category="data_access",
        message=f"User '{username}' downloaded publication '{title}' (id={publication_id})",
        username=username,
        user_id=user_id,
        ip_address=ip,
        extra_details={"publication_id": publication_id, "title": title},
    )


def log_admin_access(username: str, user_id: int, ip: str,
                     path: str, method: str) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="admin_access",
        event_category="authorization",
        message=f"Admin area accessed by '{username}'",
        username=username, user_id=user_id,
        ip_address=ip, request_path=path, http_method=method,
    )


# ---------------------------------------------------------------------------
# Administrative / user management events
# ---------------------------------------------------------------------------

def log_user_created(new_username: str, new_user_id: int,
                     created_by: str = "self-registration",
                     ip: str = None) -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="user_created",
        event_category="administrative",
        message=f"New user account created: '{new_username}'",
        username=new_username, user_id=new_user_id,
        ip_address=ip,
        extra_details={"created_by": created_by},
    )


def log_user_deleted(deleted_username: str, deleted_by: str,
                     ip: str = None) -> None:
    _emit(
        audit_log, logging.WARNING,
        event_type="user_deleted",
        event_category="administrative",
        message=f"User account deleted: '{deleted_username}' by '{deleted_by}'",
        username=deleted_username,
        ip_address=ip,
        extra_details={"deleted_by": deleted_by},
    )


def log_role_modification(target_username: str, modified_by: str,
                           change_description: str, ip: str = None) -> None:
    _emit(
        audit_log, logging.WARNING,
        event_type="role_modification",
        event_category="administrative",
        message=f"Role/permission change for '{target_username}': {change_description}",
        username=target_username,
        ip_address=ip,
        extra_details={"modified_by": modified_by, "change": change_description},
    )


# ---------------------------------------------------------------------------
# Brute-force / lockout events  (written to security.brute_force logger)
# ---------------------------------------------------------------------------

def log_account_lockout(username: str, ip: str,
                        user_agent: str = None,
                        attempt_count: int = None) -> None:
    _emit(
        brute_log, logging.WARNING,
        event_type="account_lockout",
        event_category="brute_force",
        message=f"Account locked for '{username}' from {ip}",
        username=username, ip_address=ip, user_agent=user_agent,
        extra_details={"attempt_count": attempt_count},
    )


# ---------------------------------------------------------------------------
# Honeypot events  (written to security.honeypot logger)
# ---------------------------------------------------------------------------

def log_honeypot_trigger(ip: str, path: str,
                          user_agent: str = None,
                          method: str = "POST") -> None:
    _emit(
        honeypot_log, logging.WARNING,
        event_type="honeypot_triggered",
        event_category="bot_detection",
        message=f"Honeypot triggered from {ip} on {method} {path}",
        ip_address=ip, request_path=path,
        user_agent=user_agent, http_method=method,
    )


# ---------------------------------------------------------------------------
# System events
# ---------------------------------------------------------------------------

def log_app_startup() -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="app_startup",
        event_category="system",
        message="Application startup complete",
    )


def log_app_shutdown() -> None:
    _emit(
        audit_log, logging.INFO,
        event_type="app_shutdown",
        event_category="system",
        message="Application shutdown initiated",
    )


def log_critical_exception(exc: Exception, context: str = "") -> None:
    _emit(
        audit_log, logging.CRITICAL,
        event_type="critical_exception",
        event_category="system",
        message=f"Critical exception in {context}: {type(exc).__name__}: {exc}",
        extra_details={"context": context},
    )
