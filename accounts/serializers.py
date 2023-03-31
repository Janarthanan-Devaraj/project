from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import UserProfile, AcademicInfo, CompanyInfo
from rest_framework import status, permissions, generics, mixins



User = get_user_model()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    student = serializers.BooleanField(required=True)
    alumni = serializers.BooleanField(required=True)

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            student=validated_data['student'],
            alumni=validated_data['alumni']
        )
        user.set_password(validated_data.get('password'))
        user.save()
        return user

    class Meta:
        model = User
        fields = ('email', 'student', 'alumni', 'password')


class CustomUserSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only = True)
    class Meta:
        model = User
        fields = ["id", "email", "password", "is_student", "is_alumni"]
        extra_kwargs={
            'password':{'write_only':True}
        }

class AcademicInfoSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    class Meta:
        model = AcademicInfo
        fields = "__all__"

class CompanyInfoSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    class Meta:
        model = CompanyInfo
        fields = "__all__"
        
class AcademicInfoSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    
    class Meta:
        model = AcademicInfo
        fields = "__all__"

class CompanyInfoSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    
    class Meta:
        model = CompanyInfo
        fields = "__all__"

        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('id', 'avatar', 'first_name', 'last_name', 'username', 'gender', 'dob')

# class UserProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserProfile
#         fields = ('id', 'avatar', 'first_name', 'last_name', 'username', 'gender', 'dob')

# class UserProfileDetailsSerializer(serializers.ModelSerializer):
    
#     academic_info = serializers.SerializerMethodField(read_only = True)
#     company_info = serializers.SerializerMethodField(read_only = True)

#     def get_academic_info(self, obj):
#         try:
#             academic_info = AcademicInfo.objects.get(user=obj.user)
#             return AcademicInfoSerializer(academic_info).data
#         except AcademicInfo.DoesNotExist:
#             return None

#     def get_company_info(self, obj):
#         try:
#             company_info = CompanyInfo.objects.get(user=obj.user)
#             return CompanyInfoSerializer(company_info).data
#         except CompanyInfo.DoesNotExist:
#             return None

#     class Meta:
#         model = UserProfile
#         fields = ['user', 'avatar', 'first_name', 'last_name', 'username', 'gender', 'dob', 'academic_info', 'company_info']