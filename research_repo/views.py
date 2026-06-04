from django.utils import timezone
from django.http import HttpResponse, FileResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import (
    ListView, DetailView, CreateView, UpdateView, DeleteView,
    TemplateView, View,
)
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView as DjangoLoginView, LogoutView as DjangoLogoutView
from django.urls import reverse_lazy, reverse
from django.utils.decorators import method_decorator
from honeypot.decorators import check_honeypot
from django_ratelimit.decorators import ratelimit
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from django.contrib import messages
from django.db.models import Q, Count

from .models import Publication, User, AccessGrant
from .forms import PublicationForm, AuthorshipFormSet, SignUpForm, LoginForm, AccessGrantForm
from .mixins import OwnerOrManagerMixin, FacultyVerifiedMixin, PublicationAccessMixin


@method_decorator(ratelimit(key='ip', rate='10/m', method='POST', block=True), name='dispatch')
class LoginView(DjangoLoginView):
    template_name = 'research_repo/login.html'
    form_class = LoginForm
    redirect_authenticated_user = True

    def get_success_url(self):
        return reverse_lazy('dashboard')


class LogoutView(DjangoLogoutView):
    next_page = reverse_lazy('home')


@method_decorator(check_honeypot, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='5/h', method='POST', block=True), name='dispatch')
class SignUpView(CreateView):
    model = User
    form_class = SignUpForm
    template_name = 'research_repo/signup.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = getattr(settings, 'SKIP_EMAIL_VERIFICATION', settings.DEBUG)
        user.is_email_verified = user.is_active
        if not user.is_active:
            user.email_verification_token = get_random_string(64)
        user.save()

        if not user.is_active:
            verification_link = self.request.build_absolute_uri(
                reverse('verify_email', kwargs={'token': user.email_verification_token})
            )
            send_mail(
                'Verify your ScholarVault account',
                f'Hi {user.username}, verify your account:\n{verification_link}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=True,
            )
            messages.success(
                self.request,
                'Registration successful. Check your email to verify your account.',
            )
            return redirect('login')

        messages.success(self.request, 'Account created. You can sign in now.')
        return redirect('login')


class VerifyEmailView(View):
    def get(self, request, token, *args, **kwargs):
        user = get_object_or_404(User, email_verification_token=token)
        user.is_active = True
        user.is_email_verified = True
        user.email_verification_token = None
        user.save()
        messages.success(request, 'Email verified. You can log in now.')
        return redirect('login')


class HomeView(TemplateView):
    template_name = 'research_repo/home.html'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['public_count'] = Publication.objects.filter(is_public=True).count()
        ctx['featured'] = (
            Publication.objects.filter(is_public=True)
            .select_related('uploader')
            .prefetch_related('authors__user')[:6]
        )
        return ctx


class DiscoveryView(ListView):
    """Public discovery feed — abstracts only, no PDF links in template."""
    model = Publication
    template_name = 'research_repo/discovery.html'
    context_object_name = 'publications'
    paginate_by = 12

    def get_queryset(self):
        qs = Publication.objects.filter(is_public=True).select_related('uploader')
        query = self.request.GET.get('q', '').strip()
        if query:
            qs = qs.filter(Q(title__icontains=query) | Q(abstract__icontains=query))
        return qs.order_by('-id')


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'research_repo/dashboard.html'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user = self.request.user
        ctx['my_publications'] = Publication.objects.filter(uploader=user)[:5]
        ctx['coauthored'] = Publication.objects.filter(authors__user=user).distinct()[:5]
        ctx['stats'] = {
            'uploaded': Publication.objects.filter(uploader=user).count(),
            'coauthored': Publication.objects.filter(authors__user=user).distinct().count(),
            'grants': AccessGrant.objects.filter(viewer=user, access_granted=True).count(),
        }
        return ctx


class PublicationListView(LoginRequiredMixin, ListView):
    model = Publication
    template_name = 'research_repo/publication_list.html'
    context_object_name = 'publications'
    paginate_by = 10

    def get_queryset(self):
        user = self.request.user
        query = self.request.GET.get('q', '').strip()
        queryset = Publication.objects.filter(
            Q(is_public=True)
            | Q(
                grants__viewer=user,
                grants__access_granted=True,
                grants__expires_at__gt=timezone.now(),
            )
            | Q(uploader=user)
            | Q(authors__user=user)
        ).distinct().select_related('uploader')

        if query:
            queryset = queryset.filter(
                Q(title__icontains=query) | Q(abstract__icontains=query)
            )
        return queryset.order_by('-id')


class PublicationDetailView(LoginRequiredMixin, PublicationAccessMixin, DetailView):
    model = Publication
    template_name = 'research_repo/publication_detail.html'
    context_object_name = 'publication'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['can_download'] = self.request.user.has_access_to(self.object)
        ctx['is_owner'] = self.object.uploader == self.request.user
        return ctx


class PublicationCreateView(LoginRequiredMixin, FacultyVerifiedMixin, CreateView):
    model = Publication
    form_class = PublicationForm
    template_name = 'research_repo/publication_form.html'
    success_url = reverse_lazy('publication_list')

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        if self.request.POST:
            data['authorship_formset'] = AuthorshipFormSet(self.request.POST)
        else:
            data['authorship_formset'] = AuthorshipFormSet()
        return data

    def form_valid(self, form):
        context = self.get_context_data()
        authorship_formset = context['authorship_formset']
        if authorship_formset.is_valid():
            self.object = form.save(commit=False)
            self.object.uploader = self.request.user
            self.object.save()
            authorship_formset.instance = self.object
            authorship_formset.save()
            messages.success(self.request, 'Publication uploaded successfully.')
            return redirect(self.success_url)
        return self.form_invalid(form)


class PublicationUpdateView(LoginRequiredMixin, OwnerOrManagerMixin, UpdateView):
    model = Publication
    form_class = PublicationForm
    template_name = 'research_repo/publication_form.html'
    success_url = reverse_lazy('publication_list')

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        if self.request.POST:
            data['authorship_formset'] = AuthorshipFormSet(self.request.POST, instance=self.object)
        else:
            data['authorship_formset'] = AuthorshipFormSet(instance=self.object)
        return data

    def form_valid(self, form):
        context = self.get_context_data()
        authorship_formset = context['authorship_formset']
        if authorship_formset.is_valid():
            self.object = form.save()
            authorship_formset.instance = self.object
            authorship_formset.save()
            messages.success(self.request, 'Publication updated.')
            return redirect(self.success_url)
        return self.form_invalid(form)


class PublicationDeleteView(LoginRequiredMixin, OwnerOrManagerMixin, DeleteView):
    model = Publication
    template_name = 'research_repo/publication_confirm_delete.html'
    success_url = reverse_lazy('publication_list')

    def delete(self, request, *args, **kwargs):
        messages.success(request, 'Publication removed.')
        return super().delete(request, *args, **kwargs)


@method_decorator(ratelimit(key='user', rate='10/h', method='GET', block=True), name='dispatch')
@method_decorator(ratelimit(key='ip', rate='20/h', method='GET', block=True), name='dispatch')
class PublicationDownloadView(LoginRequiredMixin, PublicationAccessMixin, View):
    """Rate-limited secure PDF download for authorized users."""

    def get_object(self):
        return get_object_or_404(Publication, pk=self.kwargs['pk'])

    def get(self, request, pk):
        publication = get_object_or_404(Publication, pk=pk)
        if not request.user.has_access_to(publication):
            raise Http404('Document not available.')
        if not publication.full_pdf:
            raise Http404('No PDF attached to this publication.')
        try:
            from security.audit_logger import log_document_download
            from security.utils import get_client_ip
            log_document_download(
                request.user.username,
                request.user.id,
                publication.id,
                publication.title,
                ip=get_client_ip(request),
            )
        except Exception:
            pass
        return redirect(publication.full_pdf.url)


class AccessGrantCreateView(LoginRequiredMixin, UserPassesTestMixin, CreateView):
    model = AccessGrant
    form_class = AccessGrantForm
    template_name = 'research_repo/access_grant_form.html'
    success_url = reverse_lazy('publication_list')

    def get_publication(self):
        if not hasattr(self, '_publication'):
            self._publication = get_object_or_404(
                Publication, id=self.kwargs.get('publication_id')
            )
        return self._publication

    def get_object(self):
        return self.get_publication()

    def test_func(self):
        publication = self.get_publication()
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return True
        return (
            publication.uploader == user
            or publication.authors.filter(user=user).exists()
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['publication'] = self.get_publication()
        return ctx

    def form_valid(self, form):
        form.instance.publication = self.get_publication()
        messages.success(self.request, 'Reviewer access granted.')
        return super().form_valid(form)


class ProfileView(LoginRequiredMixin, DetailView):
    model = User
    template_name = 'research_repo/profile.html'
    context_object_name = 'profile_user'

    def get_object(self):
        return get_object_or_404(User, username=self.kwargs.get('username'))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user = self.object
        ctx['publications'] = Publication.objects.filter(
            Q(uploader=user) | Q(authors__user=user),
            is_public=True,
        ).distinct()[:12]
        return ctx


class SettingsView(LoginRequiredMixin, TemplateView):
    template_name = 'research_repo/settings.html'
