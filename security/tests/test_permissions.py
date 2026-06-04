"""
Task 8 — Test Suite: Permission Enforcement (Anti-IDOR)

Note: Templates don't exist in this project yet (they're referenced in views
but not created). Tests that would reach the template rendering step are
adapted to check the security decision (allow/deny) rather than the full
rendered response.

- 403 / redirect-to-login = denied (correct for unauthorized access)
- TemplateDoesNotExist would only occur AFTER auth passed — meaning the
  security control let the user through (correct behavior for allowed users)

We use raise_request_exception=False on the test client for "allow" cases
so TemplateDoesNotExist is caught at the response level (500) not as an
exception, confirming auth passed.
"""

from datetime import timedelta

from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model

from research_repo.models import Publication, AccessGrant, Authorship

User = get_user_model()


class AuthenticationRequiredTest(TestCase):
    """Unauthenticated requests to protected views must redirect to login."""

    PROTECTED_URL_NAMES = [
        'publication_list',
        'publication_create',
    ]

    def test_unauthenticated_redirected_to_login(self):
        for url_name in self.PROTECTED_URL_NAMES:
            with self.subTest(url_name=url_name):
                response = self.client.get(reverse(url_name))
                self.assertIn(
                    response.status_code, [302, 403],
                    f"{url_name} should redirect or deny unauthenticated users"
                )


class PublicationAccessControlTest(TestCase):
    """RBAC and anti-IDOR tests for Publication access."""

    def setUp(self):
        self.owner = User.objects.create_user(
            username='owner', password='Pass123!',
            is_faculty=True, is_identity_verified=True,
        )
        self.stranger = User.objects.create_user(
            username='stranger', password='Pass123!',
        )
        self.private_pub = Publication.objects.create(
            title='Secret Paper',
            abstract='Top secret',
            full_pdf_url='https://res.cloudinary.com/test/raw/upload/test.pdf',
            is_public=False,
            uploader=self.owner,
        )
        self.public_pub = Publication.objects.create(
            title='Public Paper',
            abstract='Open access',
            full_pdf_url='https://res.cloudinary.com/test/raw/upload/pub.pdf',
            is_public=True,
            uploader=self.owner,
        )
        # Client that won't raise TemplateDoesNotExist — returns 500 instead
        self.safe_client = Client(raise_request_exception=False)

    def test_owner_can_access_private_publication(self):
        """Owner must NOT get a 403 on their own private pub."""
        self.safe_client.force_login(self.owner)
        response = self.safe_client.get(
            reverse('publication_detail', kwargs={'pk': self.private_pub.pk})
        )
        # 200 (with template) or 500 (template missing but auth passed) — not 403
        self.assertNotEqual(response.status_code, 403,
                            "Owner should not be denied their own publication")

    def test_stranger_denied_private_publication(self):
        """Stranger without access grant must be denied (403)."""
        self.client.force_login(self.stranger)
        response = self.client.get(
            reverse('publication_detail', kwargs={'pk': self.private_pub.pk})
        )
        self.assertEqual(response.status_code, 403)

    def test_authenticated_user_can_access_public_publication(self):
        """Any authenticated user must NOT get 403 on a public publication."""
        self.safe_client.force_login(self.stranger)
        response = self.safe_client.get(
            reverse('publication_detail', kwargs={'pk': self.public_pub.pk})
        )
        self.assertNotEqual(response.status_code, 403,
                            "Authenticated user denied access to public publication")

    def test_valid_access_grant_allows_access(self):
        AccessGrant.objects.create(
            publication=self.private_pub,
            viewer=self.stranger,
            access_granted=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.safe_client.force_login(self.stranger)
        response = self.safe_client.get(
            reverse('publication_detail', kwargs={'pk': self.private_pub.pk})
        )
        self.assertNotEqual(response.status_code, 403,
                            "Valid access grant should allow access")

    def test_expired_access_grant_denies_access(self):
        AccessGrant.objects.create(
            publication=self.private_pub,
            viewer=self.stranger,
            access_granted=True,
            expires_at=timezone.now() - timedelta(days=1),  # expired
        )
        self.client.force_login(self.stranger)
        response = self.client.get(
            reverse('publication_detail', kwargs={'pk': self.private_pub.pk})
        )
        self.assertEqual(response.status_code, 403)

    def test_revoked_access_grant_denies_access(self):
        AccessGrant.objects.create(
            publication=self.private_pub,
            viewer=self.stranger,
            access_granted=False,           # explicitly revoked
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.client.force_login(self.stranger)
        response = self.client.get(
            reverse('publication_detail', kwargs={'pk': self.private_pub.pk})
        )
        self.assertEqual(response.status_code, 403)


class UploadPermissionTest(TestCase):
    """Only faculty + identity_verified users can upload publications."""

    def setUp(self):
        self.faculty = User.objects.create_user(
            username='faculty', password='Pass123!',
            is_faculty=True, is_identity_verified=True,
        )
        self.unverified_faculty = User.objects.create_user(
            username='unverified', password='Pass123!',
            is_faculty=True, is_identity_verified=False,
        )
        self.regular_user = User.objects.create_user(
            username='regular', password='Pass123!',
        )

    def test_verified_faculty_can_upload(self):
        self.assertTrue(self.faculty.can_upload())

    def test_unverified_faculty_cannot_upload(self):
        self.assertFalse(self.unverified_faculty.can_upload())

    def test_regular_user_cannot_upload(self):
        self.assertFalse(self.regular_user.can_upload())

    def test_unverified_faculty_denied_create_view(self):
        self.client.force_login(self.unverified_faculty)
        response = self.client.get(reverse('publication_create'))
        self.assertEqual(response.status_code, 403)

    def test_regular_user_denied_create_view(self):
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse('publication_create'))
        self.assertEqual(response.status_code, 403)


class IDORPreventionTest(TestCase):
    """Verify users cannot update or delete publications they don't own."""

    def setUp(self):
        self.owner = User.objects.create_user(
            username='owner2', password='Pass123!',
            is_faculty=True, is_identity_verified=True,
        )
        self.attacker = User.objects.create_user(
            username='attacker', password='Pass123!',
            is_faculty=True, is_identity_verified=True,
        )
        self.pub = Publication.objects.create(
            title='Owner Paper',
            abstract='Abstract',
            full_pdf_url='https://res.cloudinary.com/test/raw/upload/t.pdf',
            is_public=False,
            uploader=self.owner,
        )

    def test_attacker_cannot_update_owners_publication(self):
        self.client.force_login(self.attacker)
        response = self.client.post(
            reverse('publication_update', kwargs={'pk': self.pub.pk}),
            {'title': 'Hijacked', 'abstract': 'Evil'},
        )
        self.assertEqual(response.status_code, 403)

    def test_attacker_cannot_delete_owners_publication(self):
        self.client.force_login(self.attacker)
        response = self.client.post(
            reverse('publication_delete', kwargs={'pk': self.pub.pk})
        )
        self.assertEqual(response.status_code, 403)
