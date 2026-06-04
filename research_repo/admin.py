from django.contrib import admin
from .models import Publication, Authorship, User, AccessGrant

class AuthorshipInline(admin.TabularInline):
    model = Authorship
    extra = 1  # Number of empty rows to show by default
    autocomplete_fields = ['user']  # Enable autocomplete for user selection

@admin.register(Publication)
class PublicationAdmin(admin.ModelAdmin):
    list_display = ('title', 'uploader', 'is_public', 'auto_approve_access')
    list_filter = ('is_public', 'auto_approve_access')
    inlines = [AuthorshipInline] # This links the authors to the publication

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = ('username', 'email')  # Enable search by username and email

@admin.register(AccessGrant)
class AccessGrantAdmin(admin.ModelAdmin):
    list_display = ('publication', 'viewer', 'access_granted', 'expires_at')
    list_filter = ('access_granted',)
    search_fields = ('publication__title', 'viewer__username')  # Enable search by publication title and viewer username
