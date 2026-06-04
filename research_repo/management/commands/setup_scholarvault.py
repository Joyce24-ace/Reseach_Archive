"""Create API groups and optional grading superuser from environment variables."""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group


class Command(BaseCommand):
    help = 'Create Reviewer/Premium groups and grading superuser (GRADING_* env vars).'

    def handle(self, *args, **options):
        Group.objects.get_or_create(name='Reviewers')
        Group.objects.get_or_create(name='Premium Engines')
        self.stdout.write(self.style.SUCCESS('API groups ready: Reviewers, Premium Engines'))

        import os
        username = os.getenv('GRADING_SUPERUSER_USERNAME', 'grader')
        email = os.getenv('GRADING_SUPERUSER_EMAIL', 'grader@evsu.edu.ph')
        password = os.getenv('GRADING_SUPERUSER_PASSWORD')

        if not password:
            self.stdout.write(self.style.WARNING(
                'Set GRADING_SUPERUSER_PASSWORD to create the grading superuser.'
            ))
            return

        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={'email': email, 'is_staff': True, 'is_superuser': True},
        )
        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_faculty = True
        user.is_identity_verified = True
        user.is_active = True
        user.save()
        action = 'Created' if created else 'Updated'
        self.stdout.write(self.style.SUCCESS(f'{action} grading superuser: {username}'))
