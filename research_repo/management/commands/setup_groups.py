from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand
from research_repo.models import Publication 


class Command(BaseCommand):
    help = 'Set up user groups and permissions for the research repository'

    def handle(self, *args, **options):

        content_type = ContentType.objects.get_for_model(Publication)

        groups_permissions = {
            'Faculty': [
                'add_publication',
                'change_publication',
                'delete_publication',
                'view_publication',
                'download_publication',
            ],

            'Peer Reviewer': [
                'view_publication',
                'download_publication',
                'review_publication',
            ],

            'Guest': [
                'view_publication',
            ],
        }

        custom_permissions = [
            ("download_publication", "Can download publication"),
            ("review_publication", "Can review publication"),
        ]

        for codename, name in custom_permissions:
            Permission.objects.get_or_create(
                codename=codename,
                content_type=content_type,
                defaults={"name": name},
            )

        for group_name, perms in groups_permissions.items():
            group, created = Group.objects.get_or_create(name=group_name)

            if created:
                self.stdout.write(self.style.SUCCESS(f'Created group: {group_name}'))
            else:
                self.stdout.write(self.style.WARNING(f'Updating group: {group_name}'))

            group.permissions.clear()

            for perm_codename in perms:
                perm = Permission.objects.filter(
                    codename=perm_codename,
                    content_type=content_type
                ).first()

                if perm:
                    group.permissions.add(perm)
                    self.stdout.write(
                        self.style.SUCCESS(f'Added "{perm_codename}" → {group_name}')
                    )
                else:
                    self.stdout.write(
                        self.style.ERROR(f'Permission not found: {perm_codename}')
                    )

        self.stdout.write(self.style.SUCCESS("Groups and permissions setup complete."))