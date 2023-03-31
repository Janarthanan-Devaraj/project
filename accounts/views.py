from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

from .serializers import(CustomUserSerializer, User, LoginSerializer, 
                         UserProfile, AcademicInfo, 
                         CompanyInfo, AcademicInfoSerializer,
                         CompanyInfoSerializer, UserProfileSerializer,
                         UserProfileDetailsSerializer)

from rest_framework import status, generics, mixins

from rest_framework.permissions import IsAuthenticated

class SignUpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        })
        
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get("email")
        password = serializer.data.get("password")

        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({"error": "Invalid email or password"})

        refresh = RefreshToken.for_user(user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id" : user.id
        })

class UserProfileListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class AcademicInfoListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class CompanyInfoListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class AcademicInfoListCreateAPIView(generics.ListCreateAPIView):
    queryset = AcademicInfo.objects.all()
    serializer_class = AcademicInfoSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CompanyInfoListCreateAPIView(generics.ListCreateAPIView):
    queryset = CompanyInfo.objects.all()
    serializer_class = CompanyInfoSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class UserRetrieveView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileDetailsSerializer

    def get_object(self):
        return self.request.user

# class UserProfileListAPIView(generics.CreateAPIView):
#     permission_classes = [IsAuthenticated]
#     queryset = UserProfile.objects.all()
#     serializer_class = UserProfileSerializer
#     lookup_field = 'pk'


# class UserProfileAPIView(APIView):

#     def get(self, request, format=None):
#         user_profile = UserProfile.objects.get(user=request.user)
#         serializer = UserProfileSerializer(user_profile)
#         return Response(serializer.data)
    
#     def post(self, request, format=None):
#         user = user.objects.get(user = request.user)
#         request.data['user'] = user
#         serializer = UserProfileSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)