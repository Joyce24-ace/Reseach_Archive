# research_repo/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LoginView, LogoutView, PublicationViewSet

router = DefaultRouter()
router.register(r'publications', PublicationViewSet, basename='publication')

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='api-login'),
    path('auth/logout/', LogoutView.as_view(), name='api-logout'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('', include(router.urls)),
]