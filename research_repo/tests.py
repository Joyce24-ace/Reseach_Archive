from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from .models import User, Publication, AccessGrant

class RepositorySecurityTest(TestCase):
    def setUp(self):
        # Create users
        self.faculty = User.objects.create(username='prof', is_faculty=True, is_identity_verified=True)
        self.guest = User.objects.create(username='guest', is_faculty=False)
        self.pub = Publication.objects.create(title="Research 1", uploader=self.faculty)

    def test_faculty_upload_permission(self):
        self.assertTrue(self.faculty.can_upload())
        self.assertFalse(self.guest.can_upload())

    def test_access_grant_expiration(self):
        # Give access that expired 1 day ago
        grant = AccessGrant.objects.create(
            publication=self.pub, 
            viewer=self.guest, 
            access_granted=True,
            expires_at=timezone.now() - timedelta(days=1)
        )
        self.assertFalse(self.guest.has_access_to(self.pub))