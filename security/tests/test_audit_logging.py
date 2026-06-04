"""
Task 8 — Test Suite: Audit Log Generation
Validates that all required audit events are emitted with correct
structure and fields.
"""

import json
import logging
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from security.audit_logger import (
    log_login_success,
    log_login_failure,
    log_logout,
    log_permission_denied,
    log_user_created,
    log_user_deleted,
    log_account_lockout,
    log_honeypot_trigger,
    log_admin_access,
    log_app_startup,
    log_critical_exception,
)
from security.formatters import JSONAuditFormatter

User = get_user_model()


class JSONFormatterTest(TestCase):
    """Verifies the JSON formatter produces valid, spec-compliant records."""

    def _make_record(self, **kwargs):
        record = logging.LogRecord(
            name='security.audit',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='test message',
            args=(),
            exc_info=None,
        )
        for k, v in kwargs.items():
            setattr(record, k, v)
        return record

    def test_formatter_produces_valid_json(self):
        formatter = JSONAuditFormatter()
        record = self._make_record(
            event_type='login_success',
            event_category='authentication',
            username='alice',
            user_id=1,
            ip_address='10.0.0.1',
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed['event_type'], 'login_success')
        self.assertEqual(parsed['username'], 'alice')
        self.assertIn('timestamp', parsed)
        self.assertIn('severity', parsed)
        self.assertIn('event_id', parsed)

    def test_formatter_excludes_none_values(self):
        formatter = JSONAuditFormatter()
        record = self._make_record(event_type='test')
        output = formatter.format(record)
        parsed = json.loads(output)
        # None-valued keys should be stripped
        for v in parsed.values():
            self.assertIsNotNone(v)

    def test_timestamp_is_utc_iso8601(self):
        formatter = JSONAuditFormatter()
        record = self._make_record(event_type='test')
        output = formatter.format(record)
        parsed = json.loads(output)
        ts = parsed['timestamp']
        self.assertTrue(ts.endswith('Z'), f"Timestamp not UTC: {ts}")
        self.assertRegex(ts, r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z')


class AuditLoggerFunctionTest(TestCase):
    """Unit-tests each audit_logger helper to confirm it emits correctly."""

    def test_log_login_success(self):
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_login_success('alice', 1, '10.0.0.1', 'Agent/1', '/login/')
        self.assertTrue(any('login_success' in line for line in cm.output),
                        f"Expected login_success in: {cm.output}")

    def test_log_login_failure(self):
        with self.assertLogs('security.audit', level='WARNING') as cm:
            log_login_failure('alice', '10.0.0.1')
        self.assertTrue(any('login_failure' in line for line in cm.output),
                        f"Expected login_failure in: {cm.output}")

    def test_log_logout(self):
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_logout('alice', 1, '10.0.0.1')
        self.assertTrue(any('logout' in line for line in cm.output),
                        f"Expected logout in: {cm.output}")

    def test_log_permission_denied(self):
        with self.assertLogs('security.audit', level='WARNING') as cm:
            log_permission_denied('alice', 1, '10.0.0.1', '/admin/', 'GET')
        self.assertTrue(any('permission_denied' in line for line in cm.output),
                        f"Expected permission_denied in: {cm.output}")

    def test_log_user_created(self):
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_user_created('newuser', 99, ip='10.0.0.1')
        self.assertTrue(any('user_created' in line for line in cm.output),
                        f"Expected user_created in: {cm.output}")

    def test_log_user_deleted(self):
        with self.assertLogs('security.audit', level='WARNING') as cm:
            log_user_deleted('olduser', 'admin')
        self.assertTrue(any('user_deleted' in line for line in cm.output),
                        f"Expected user_deleted in: {cm.output}")

    def test_log_account_lockout(self):
        with self.assertLogs('security.brute_force', level='WARNING') as cm:
            log_account_lockout('alice', '10.0.0.1')
        self.assertTrue(any('account_lockout' in line for line in cm.output),
                        f"Expected account_lockout in: {cm.output}")

    def test_log_honeypot_trigger(self):
        with self.assertLogs('security.honeypot', level='WARNING') as cm:
            log_honeypot_trigger('10.0.0.1', '/login/')
        self.assertTrue(any('honeypot_triggered' in line for line in cm.output),
                        f"Expected honeypot_triggered in: {cm.output}")

    def test_log_admin_access(self):
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_admin_access('admin', 1, '10.0.0.1', '/admin/', 'GET')
        self.assertTrue(any('admin_access' in line for line in cm.output),
                        f"Expected admin_access in: {cm.output}")

    def test_log_app_startup(self):
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_app_startup()
        self.assertTrue(any('app_startup' in line for line in cm.output),
                        f"Expected app_startup in: {cm.output}")

    def test_log_critical_exception(self):
        with self.assertLogs('security.audit', level='CRITICAL') as cm:
            log_critical_exception(ValueError("test error"), context="unit_test")
        self.assertTrue(any('critical_exception' in line for line in cm.output),
                        f"Expected critical_exception in: {cm.output}")


class AuditLogIntegrationTest(TestCase):
    """
    Integration: verifies audit events fire during actual HTTP requests.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username='integuser',
            password='SecurePass123!',
        )
        self.login_url = reverse('login')

    def test_admin_access_is_logged(self):
        """Accessing /admin/ as a staff user must produce an admin_access log."""
        admin_user = User.objects.create_superuser(
            username='adminuser', password='AdminPass123!', email='a@a.com'
        )
        self.client.force_login(User.objects.get(username='adminuser'))
        with self.assertLogs('security.audit', level='INFO') as cm:
            self.client.get('/admin/', REMOTE_ADDR='10.0.0.1')
        self.assertTrue(
            any('admin_access' in line for line in cm.output),
            "Expected admin_access event in audit log"
        )
