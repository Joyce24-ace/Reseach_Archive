"""
Task 3 — JSON Audit Log Formatter
Produces structured JSON log records consumable by SIEM tools.
"""

import json
import logging
import traceback
from datetime import timezone as dt_timezone


class JSONAuditFormatter(logging.Formatter):
    """
    Converts a LogRecord into a single-line JSON string.
    Every field required by the compliance spec is included.
    """

    EXCLUDED_RECORD_ATTRS = {
        'args', 'exc_info', 'exc_text', 'filename', 'funcName',
        'levelno', 'lineno', 'message', 'module', 'msecs',
        'msg', 'name', 'pathname', 'process', 'processName',
        'relativeCreated', 'stack_info', 'thread', 'threadName',
    }

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()

        log_entry = {
            "timestamp": self._utc_isotime(record),
            "severity": record.levelname,
            "logger": record.name,
            "event_type": getattr(record, "event_type", "generic"),
            "event_category": getattr(record, "event_category", "system"),
            "event_id": getattr(record, "event_id", str(__import__('uuid').uuid4())),
            "message": record.message,
            # identity
            "username": getattr(record, "username", None),
            "user_id": getattr(record, "user_id", None),
            # request context
            "ip_address": getattr(record, "ip_address", None),
            "user_agent": getattr(record, "user_agent", None),
            "request_path": getattr(record, "request_path", None),
            "http_method": getattr(record, "http_method", None),
            # optional extras passed by callers
            "extra": self._collect_extras(record),
        }

        # Attach formatted exception if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        elif record.exc_text:
            log_entry["exception"] = record.exc_text

        # Remove None values to keep logs lean
        log_entry = {k: v for k, v in log_entry.items() if v is not None}

        return json.dumps(log_entry, default=str)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _utc_isotime(record: logging.LogRecord) -> str:
        """Return ISO-8601 UTC timestamp."""
        from datetime import datetime
        return datetime.fromtimestamp(
            record.created, tz=dt_timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _collect_extras(self, record: logging.LogRecord) -> dict:
        """Collect any caller-supplied extra fields not in the standard set."""
        standard = set(logging.LogRecord(
            '', 0, '', 0, '', (), None
        ).__dict__.keys()) | self.EXCLUDED_RECORD_ATTRS | {
            'event_type', 'event_category', 'event_id',
            'username', 'user_id', 'ip_address', 'user_agent',
            'request_path', 'http_method', 'message',
        }
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in standard and not k.startswith('_')
        }
        return extras if extras else None
