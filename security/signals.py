"""
Task 1 & 3 — Django Signals for Audit Logging
Hooks into Django's built-in auth signals and axes signals to emit
structured audit events without touching any view code.

Connected in security/apps.py → ready().
"""

import logging
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from .audit_logger import (
    log_login_success,
    log_login_failure,
    log_logout,
    log_user_created,
    log_user_deleted,
    log_account_lockout,
)
from .utils import get_client_ip

brute_log = logging.getLogger("security.brute_force")


# ---------------------------------------------------------------------------
# Authentication signals
# ---------------------------------------------------------------------------

@receiver(user_logged_in)
def on_user_logged_in(sender, request, user, **kwargs):
    """Fires on every successful Django session login."""
    ip = get_client_ip(request) if request else "unknown"
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    path = request.path if request else ""
    log_login_success(
        username=user.username,
        user_id=user.id,
        ip=ip,
        user_agent=ua,
        path=path,
    )


@receiver(user_logged_out)
def on_user_logged_out(sender, request, user, **kwargs):
    """Fires on every Django session logout."""
    if not user:
        return
    ip = get_client_ip(request) if request else "unknown"
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    log_logout(username=user.username, user_id=user.id, ip=ip, user_agent=ua)


@receiver(user_login_failed)
def on_user_login_failed(sender, credentials, request, **kwargs):
    """Fires on every failed authentication attempt."""
    ip = get_client_ip(request) if request else "unknown"
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    path = request.path if request else ""
    username = credentials.get("username", "unknown")
    log_login_failure(username=username, ip=ip, user_agent=ua, path=path)


# ---------------------------------------------------------------------------
# django-axes lockout signal
# ---------------------------------------------------------------------------

def on_axes_lockout(sender, request, username=None, **kwargs):
    """
    Called by axes.signals.user_locked_out when an account is locked out.
    axes 8.x sends: sender="axes", request=request, username=username
    """
    ip = get_client_ip(request) if request else "unknown"
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    log_account_lockout(username=username or "unknown", ip=ip, user_agent=ua)
    if request:
        request._axes_lockout = True


# ---------------------------------------------------------------------------
# User lifecycle signals
# ---------------------------------------------------------------------------

def _connect_user_signals():
    """
    Connect post_save / post_delete for the custom User model.
    Called lazily from SecurityConfig.ready() after app registry is loaded.
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()

    @receiver(post_save, sender=User, weak=False)
    def on_user_saved(sender, instance, created, **kwargs):
        if created:
            log_user_created(
                new_username=instance.username,
                new_user_id=instance.id,
                created_by="admin_or_registration",
            )

    @receiver(post_delete, sender=User, weak=False)
    def on_user_deleted(sender, instance, **kwargs):
        log_user_deleted(
            deleted_username=instance.username,
            deleted_by="system",
        )
