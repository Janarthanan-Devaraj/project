from django.urls import path

from .views import SignUpView, LoginView, UserProfileListCreateAPIView, AcademicInfoListCreateAPIView, CompanyInfoListCreateAPIView

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register/', SignUpView.as_view(),name='register' ),
    path('login/', LoginView.as_view(),name='login' ),
    path('profile/', UserProfileListCreateAPIView.as_view(), name='user-profile-list-create'),
    path('profile/create/', UserProfileListCreateAPIView.as_view(), name = 'profile-create'),
    path('academic-info/', AcademicInfoListCreateAPIView.as_view(), name='academic-info-list-create'),
    path('company-info/', CompanyInfoListCreateAPIView.as_view(), name='company-info-list-create'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]