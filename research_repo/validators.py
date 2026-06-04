"""
Institutional email domain validator.

Used by:
  - research_repo.forms.SignUpForm       (web registration)
  - publication_api.serializers           (API registration)
  - research_repo.models.User.clean()    (model-level safeguard)

The allowed domain is configured via settings.ALLOWED_EMAIL_DOMAIN
(default: 'evsu.edu.ph'), which can be overridden per-environment
using the ALLOWED_EMAIL_DOMAIN environment variable.
"""

from django.conf import settings
from django.core.exceptions import ValidationError


def get_allowed_domain() -> str:
    """Return the configured institutional email domain (lowercase)."""
    return getattr(settings, 'ALLOWED_EMAIL_DOMAIN', 'evsu.edu.ph').lower()


def validate_institutional_email(email: str) -> None:
    """
    Raise ValidationError if the email address does not belong to
    the institution's domain (settings.ALLOWED_EMAIL_DOMAIN).

    Accepts:  student@evsu.edu.ph
    Rejects:  student@gmail.com, student@yahoo.com, etc.
    """
    if not email:
        return  # Let Django's required-field validators handle empty values

    allowed_domain = get_allowed_domain()
    email_lower = email.strip().lower()

    if not email_lower.endswith('@' + allowed_domain):
        raise ValidationError(
            'Only @%(domain)s email addresses are accepted. '
            'Please use your institutional email.',
            code='invalid_email_domain',
            params={'domain': allowed_domain},
        )
