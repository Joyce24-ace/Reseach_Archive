from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('', views.HomeView.as_view(), name='home'),
    path('discover/', views.DiscoveryView.as_view(), name='discovery'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('register/', views.SignUpView.as_view(), name='signup'),
    path('signup/', views.SignUpView.as_view(), name='signup_alt'),
    path('verify/<str:token>/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('publications/', views.PublicationListView.as_view(), name='publication_list'),
    path('publications/create/', views.PublicationCreateView.as_view(), name='publication_create'),
    path('publications/<int:pk>/', views.PublicationDetailView.as_view(), name='publication_detail'),
    path('publications/<int:pk>/update/', views.PublicationUpdateView.as_view(), name='publication_update'),
    path('publications/<int:pk>/delete/', views.PublicationDeleteView.as_view(), name='publication_delete'),
    path(
        'publications/<int:pk>/download/',
        views.PublicationDownloadView.as_view(),
        name='publication_download',
    ),
    path(
        'publications/<int:publication_id>/grant-access/',
        views.AccessGrantCreateView.as_view(),
        name='grant_access',
    ),
    path('profile/<str:username>/', views.ProfileView.as_view(), name='profile'),
    path('settings/', views.SettingsView.as_view(), name='settings'),
]
