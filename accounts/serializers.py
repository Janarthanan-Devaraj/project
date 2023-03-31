from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import UserProfile, AcademicInfo, CompanyInfo
from rest_framework import status, permissions, generics, mixins



User = get_user_model()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class CustomUserSerializer(serializers.ModelSerializer):
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
        extra_kwargs={
            'password':{'write_only':True}
        }

        
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


class UserProfileDetailsSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer()
    academic_model = AcademicInfoSerializer(source='student_model')
    company_model = CompanyInfoSerializer(source='alumni_model')

    class Meta:
        model = User
        fields = ('id', 'email', 'student', 'alumni', 'user_profile', 'academic_model', 'company_model')