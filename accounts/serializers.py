from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

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
