from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from research_repo.models import Publication
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.throttling import UserRateThrottle
from .serializers import LoginSerializer, LogoutSerializer, PublicationSerializer


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'is_faculty': user.is_faculty,
                'is_identity_verified': user.is_identity_verified,
                'can_upload': user.can_upload()
            }
        }, status=status.HTTP_200_OK)
    

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Successfully logged out."}, 
            status=status.HTTP_205_RESET_CONTENT
        )


class PublicationViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]
    page_size = 10
    throttle_classes = [UserRateThrottle]
    def _get_secure_queryset(self, user):
        """
        Helper method to securely isolate visible publications using Q objects.
        Optimized with select_related and prefetch_related to avoid N+1 queries.
        """
        base_queryset = Publication.objects.select_related('uploader').prefetch_related('authors__user')

        if not user or user.is_anonymous:
            return base_queryset.filter(is_public=True)
            
        if user.is_superuser:
            return base_queryset.all()
            
        return base_queryset.filter(
            Q(is_public=True) |
            Q(uploader=user) |
            Q(authors__user=user) |
            Q(grants__viewer=user, grants__access_granted=True, grants__expires_at__gt=timezone.now())
        ).distinct()

    def list(self, request):
        """GET /publications/"""
        queryset = self._get_secure_queryset(request.user)
        serializer = PublicationSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        """POST /publications/"""
        if not request.user.can_upload():
            return Response(
                {"detail": "Your account is not authorized to upload publications."},
                status=status.HTTP_403_FORBIDDEN
            )

        if hasattr(request.data, 'dict'):
            data = request.data.dict()
        else:
            data = request.data.copy()
            
        serializer = PublicationSerializer(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        serializer.save(uploader=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        """GET /publications/{id}/"""
        queryset = self._get_secure_queryset(request.user)
        publication = get_object_or_404(queryset, pk=pk)
        serializer = PublicationSerializer(publication, context={'request': request})
        return Response(serializer.data)

    def update(self, request, pk=None):
        """PUT /publications/{id}/"""
        if request.user.is_superuser:
            queryset = Publication.objects.all()
        else:
            queryset = Publication.objects.filter(
                Q(uploader=request.user) | Q(authors__user=request.user)
            ).distinct()
            
        publication = get_object_or_404(queryset, pk=pk)
            
        serializer = PublicationSerializer(publication, data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def destroy(self, request, pk=None):
        """DELETE /publications/{id}/"""
        if request.user.is_superuser:
            queryset = Publication.objects.all()
        else:
            queryset = Publication.objects.filter(uploader=request.user)
            
        publication = get_object_or_404(queryset, pk=pk)
        publication.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)