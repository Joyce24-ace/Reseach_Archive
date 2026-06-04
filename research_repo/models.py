from django.db import models
from django.contrib.auth.models import AbstractUser, Group
from django.utils import timezone
from datetime import timedelta
from cloudinary_storage.storage import  MediaCloudinaryStorage
from cloudinary.models import CloudinaryField



class User(AbstractUser):
    is_faculty = models.BooleanField(default=False)
    is_identity_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='verified_users')
    description = models.TextField(blank=True, null=True, verbose_name="User Description")
    id_document = CloudinaryField('image', blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.username

    def can_upload(self):
        return self.is_faculty and self.is_identity_verified

    def has_access_to(self, publication):
        # Admins, Owners, and Authors have full access
        if self.is_superuser or publication.is_owner_or_author(self):
            return True
        # Check valid AccessGrant
        return publication.grants.filter(viewer=self, access_granted=True, expires_at__gt=timezone.now()).exists()

class Publication(models.Model):
    title = models.CharField(max_length=255)
    abstract = models.TextField()
    full_pdf = models.FileField(upload_to='publications/', storage=MediaCloudinaryStorage(), blank=True, null=True)
        
    is_public = models.BooleanField(default=False)
    auto_approve_access = models.BooleanField(default=False)
    uploader = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_publications')

    def __str__(self):
        return self.title
    
    def is_owner_or_author(self, user):
        return self.uploader == user or self.authors.filter(user=user).exists()
    

class Authorship(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='authored_publications')
    publication = models.ForeignKey(Publication, on_delete=models.CASCADE, related_name='authors')
    contribution_role = models.CharField(max_length=50) # e.g., 'Lead Researcher', 'Editor'

class AccessGrant(models.Model):
    publication = models.ForeignKey(Publication, on_delete=models.CASCADE, related_name='grants')
    viewer = models.ForeignKey(User, on_delete=models.CASCADE)
    access_granted = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=30)
        super().save(*args, **kwargs)

    def renew_access(self):
        self.expires_at = timezone.now() + timedelta(days=30)
        self.save()    