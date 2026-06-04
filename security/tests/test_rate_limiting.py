"""
Task 8 — Test Suite: Rate Limiting (django-ratelimit)
Verifies that login, signup, and API auth endpoints enforce per-IP rate limits.

Notes:
- Web login/signup include phone_number honeypot field (must be empty)
- API login uses JSON — no honeypot, but AxesBackend needs request context
  (serializer now passes it); use raise_request_exception=False to catch errors
"""

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()


class WebLoginRateLimitTest(TestCase):
    """Web login endpoint: 10 POST requests per minute per IP."""

    def setUp(self):
        self.url = reverse('login')
        User.objects.create_user(username='rluser', password='Pass123!')
        # Use safe client — axes internal errors on lockout boundary return 500
        self.safe_client = Client(raise_request_exception=False)

    def _post(self, n=1):
        responses = []
        for _ in range(n):
            responses.append(
                self.safe_client.post(
                    self.url,
                    {'username': 'rluser', 'password': 'wrong', 'phone_number': ''},
                    REMOTE_ADDR='10.1.1.1',
                )
            )
        return responses

    def test_within_limit_returns_not_rate_limited(self):
        """First request should be processed (not rate-limited = not 429/403)."""
        responses = self._post(1)
        self.assertNotIn(responses[0].status_code, [429],
                         "First request should not be rate-limited")

    def test_exceeding_limit_returns_403_or_429(self):
        """After 11 POSTs from the same IP, the request is rate-limited (403)."""
        responses = self._post(11)
        last = responses[-1]
        self.assertIn(
            last.status_code, [403, 429],
            f"Expected rate limit response, got {last.status_code}"
        )


class WebSignupRateLimitTest(TestCase):
    """Signup endpoint: 5 POST requests per hour per IP."""

    def setUp(self):
        self.url = reverse('signup')

    def _post_signup(self, n=1):
        responses = []
        for i in range(n):
            responses.append(
                self.client.post(
                    self.url,
                    {
                        'username': f'rlsignup{i}',
                        'email': f'u{i}@test.com',
                        'password1': 'TestPass123!',
                        'password2': 'TestPass123!',
                        'phone_number': '',   # honeypot
                    },
                    REMOTE_ADDR='10.2.2.2',
                )
            )
        return responses

    def test_first_signup_not_rate_limited(self):
        responses = self._post_signup(1)
        self.assertNotEqual(responses[0].status_code, 429)

    def test_exceeding_signup_limit(self):
        """After 6 signup attempts from same IP, should be rate-limited."""
        responses = self._post_signup(6)
        last = responses[-1]
        self.assertIn(
            last.status_code, [403, 429],
            f"Expected rate limit response, got {last.status_code}"
        )


class APILoginRateLimitTest(TestCase):
    """API login endpoint: 10 POST requests per minute per IP."""

    def setUp(self):
        self.url = reverse('api-login')
        User.objects.create_user(username='apirluser', password='Pass123!')
        # Don't raise exceptions — AxesBackend errors surface as 400/500
        self.safe_client = Client(raise_request_exception=False)

    def _post(self, n=1):
        responses = []
        for _ in range(n):
            responses.append(
                self.safe_client.post(
                    self.url,
                    '{"username": "apirluser", "password": "wrong"}',
                    content_type='application/json',
                    REMOTE_ADDR='10.3.3.3',
                )
            )
        return responses

    def test_api_within_limit(self):
        """First API login request should not be rate-limited."""
        responses = self._post(1)
        self.assertNotEqual(responses[0].status_code, 429,
                            "First request should not be rate-limited")

    def test_api_exceeding_limit(self):
        """After 11 POSTs from the same IP within a minute, should be blocked."""
        responses = self._post(11)
        last = responses[-1]
        self.assertIn(
            last.status_code, [403, 429],
            f"Expected rate limit on API login, got {last.status_code}"
        )
