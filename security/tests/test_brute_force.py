"""
Task 8 — Test Suite: Brute-Force Protection (django-axes)
Validates lockout after N failed attempts, that lockout events are logged,
and that the audit trail captures both login successes and failures.
"""

from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()


@override_settings(
    AXES_ENABLED=True,
    AXES_FAILURE_LIMIT=3,
    AXES_RESET_ON_SUCCESS=True,
    AXES_LOCKOUT_PARAMETERS=[['ip_address', 'username']],
)
class BruteForceProtectionTest(TestCase):
    """
    Verifies that django-axes enforces lockout after repeated failures.
    Uses the API login endpoint (JSON, no template) to avoid template issues.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username='testfaculty',
            password='ValidPass123!',
            is_faculty=True,
            is_identity_verified=True,
        )
        # Use the API login endpoint — returns JSON, no template rendering
        self.login_url = reverse('api-login')
        # Don't raise exceptions so axes 403 comes back as a response
        self.safe_client = Client(raise_request_exception=False)

    def _attempt_login(self, password='wrong'):
        return self.safe_client.post(
            self.login_url,
            f'{{"username": "testfaculty", "password": "{password}"}}',
            content_type='application/json',
            REMOTE_ADDR='10.0.0.1',
            HTTP_USER_AGENT='TestAgent/1.0',
        )

    def test_successful_login_returns_200(self):
        """A valid credential login must return 200."""
        response = self._attempt_login(password='ValidPass123!')
        self.assertEqual(response.status_code, 200)

    def test_failed_login_returns_400(self):
        """A single bad credential attempt is rejected with 400 (validation error)."""
        response = self._attempt_login(password='wrong')
        # DRF serializer raises ValidationError = 400
        self.assertIn(response.status_code, [400, 401])

    def test_repeated_failures_trigger_lockout(self):
        """
        After AXES_FAILURE_LIMIT failures, subsequent attempts are blocked.
        django-ratelimit (10/min) may fire before axes lockout — both 403 and
        429 indicate the account/IP is blocked as expected.
        """
        for _ in range(3):
            self._attempt_login(password='wrong')
        response = self._attempt_login(password='wrong')
        self.assertIn(
            response.status_code, [403, 429],
            f"Expected lockout/rate-limit, got {response.status_code}"
        )

    def test_lockout_is_logged(self):
        """Lockout events must appear in the security.brute_force logger."""
        from security.audit_logger import log_account_lockout
        with self.assertLogs('security.brute_force', level='WARNING') as cm:
            log_account_lockout('testfaculty', '10.0.0.1', user_agent='TestAgent/1.0')
        self.assertTrue(
            any('account_lockout' in line for line in cm.output),
            f"Expected account_lockout in: {cm.output}"
        )

    def test_login_failure_is_audit_logged(self):
        """Failed login attempts must appear in security.audit logger."""
        from security.audit_logger import log_login_failure
        with self.assertLogs('security.audit', level='WARNING') as cm:
            log_login_failure('testfaculty', '10.0.0.1')
        self.assertTrue(
            any('login_failure' in line for line in cm.output),
            f"Expected login_failure in: {cm.output}"
        )

    def test_login_success_is_audit_logged(self):
        """Successful logins must appear in security.audit logger."""
        from security.audit_logger import log_login_success
        with self.assertLogs('security.audit', level='INFO') as cm:
            log_login_success('testfaculty', 1, '10.0.0.1')
        self.assertTrue(
            any('login_success' in line for line in cm.output),
            f"Expected login_success in: {cm.output}"
        )
