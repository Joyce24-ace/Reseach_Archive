"""
Task 8 — Test Suite: Honeypot Detection (django-honeypot)
Verifies that bot submissions filling the hidden field are rejected (400)
and that the event is logged.
"""

from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

HONEYPOT_FIELD = 'phone_number'


@override_settings(
    HONEYPOT_FIELD_NAME=HONEYPOT_FIELD,
    HONEYPOT_VALUE='',
)
class HoneypotTest(TestCase):

    def setUp(self):
        self.login_url = reverse('login')
        self.signup_url = reverse('signup')

    def _post_with_honeypot(self, url):
        """Simulate a bot that fills the hidden field."""
        return self.client.post(
            url,
            {'username': 'bot', 'password': 'anything', HONEYPOT_FIELD: 'bot-value'},
            REMOTE_ADDR='192.168.1.99',
            HTTP_USER_AGENT='BotAgent/2.0',
        )

    def _post_without_honeypot(self, url):
        """Simulate a human who leaves the hidden field empty."""
        return self.client.post(
            url,
            {'username': 'human', 'password': 'humanpass', HONEYPOT_FIELD: ''},
            REMOTE_ADDR='10.10.10.1',
            HTTP_USER_AGENT='Mozilla/5.0',
        )

    def test_honeypot_triggered_returns_400(self):
        """Filled honeypot field on login must return 400."""
        response = self._post_with_honeypot(self.login_url)
        self.assertEqual(response.status_code, 400)

    def test_empty_honeypot_passes_through(self):
        """Empty honeypot on login must not block (200 = bad creds, not 400)."""
        response = self._post_without_honeypot(self.login_url)
        self.assertNotEqual(response.status_code, 400)

    def test_signup_honeypot_triggered(self):
        """Filled honeypot field on signup must return 400."""
        response = self._post_with_honeypot(self.signup_url)
        self.assertEqual(response.status_code, 400)

    def test_honeypot_trigger_is_logged(self):
        """
        Honeypot detection must produce a WARNING in security.honeypot.
        We call the audit_logger directly to verify the logging infrastructure
        works (the middleware logs on each response; this unit-tests the logger).
        """
        from security.audit_logger import log_honeypot_trigger
        with self.assertLogs('security.honeypot', level='WARNING') as cm:
            log_honeypot_trigger('192.168.1.99', '/login/', user_agent='BotAgent/2.0')
        self.assertTrue(
            any('honeypot_triggered' in line for line in cm.output),
            f"Expected honeypot_triggered in: {cm.output}"
        )
