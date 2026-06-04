"""
SecurityConfig — AppConfig for the security module.
Wires up all signals in ready() so the app registry is fully loaded first.
"""

from django.apps import AppConfig
import logging

audit_log = logging.getLogger("security.audit")


class SecurityConfig(AppConfig):
    name = "security"
    verbose_name = "DevSecOps Security Module"

    def ready(self):
        """
        Called once the Django app registry is ready.
        - Connects auth signals for audit logging
        - Connects django-axes lockout signal
        - Connects user lifecycle signals
        - Emits app_startup event
        """
        # Import and connect signals
        from . import signals  # noqa: F401 — triggers @receiver decorators
        from .signals import on_axes_lockout, _connect_user_signals

        # Connect user lifecycle signals (needs User model)
        _connect_user_signals()

        # Connect axes lockout signal
        try:
            from axes.signals import user_locked_out
            user_locked_out.connect(
                on_axes_lockout,
                dispatch_uid='security.on_axes_lockout'
            )
        except ImportError:
            audit_log.warning(
                "django-axes not installed; brute-force lockout signal not connected.",
                extra={"event_type": "config_warning", "event_category": "system"},
            )

        # Connect honeypot signal
        try:
            from honeypot.signals import honeypot_detected
            from .honeypot_handlers import on_honeypot_detected
            honeypot_detected.connect(on_honeypot_detected)
        except (ImportError, AttributeError):
            # django-honeypot doesn't emit a signal in all versions;
            # the middleware fallback in AuditLogMiddleware covers this case.
            pass

        # Emit startup event
        from .audit_logger import log_app_startup
        log_app_startup()
