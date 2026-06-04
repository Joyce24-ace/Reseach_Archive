"""
Object-level permission mixins for portfolio and publication views.
"""

from django.contrib.auth.mixins import UserPassesTestMixin


class OwnerOrManagerMixin(UserPassesTestMixin):
    """
    Researchers may edit only their own portfolio records.
    Staff and superusers may manage all records.
  """

    def test_func(self):
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return True
        obj = self.get_object()
        if getattr(obj, 'uploader', None) == user:
            return True
        if hasattr(obj, 'authors'):
            return obj.authors.filter(user=user).exists()
        return False


class FacultyVerifiedMixin(UserPassesTestMixin):
    """Only verified faculty may upload publications."""

    def test_func(self):
        return self.request.user.can_upload()


class PublicationAccessMixin(UserPassesTestMixin):
    """Read access: public, owner, co-author, granted reviewer, or staff."""

    def test_func(self):
        publication = self.get_object()
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return True
        if publication.is_public:
            return True
        return user.has_access_to(publication)
