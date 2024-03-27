from rest_framework import serializers
from .models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password']

class UserVerificationSerializer(serializers.Serializer):
    email_or_username = serializers.CharField()
    otp = serializers.CharField()

class UserLoginSerializer(serializers.Serializer):
    email_or_username = serializers.CharField()
    otp = serializers.CharField()

class UserForgotPasswordSerializer(serializers.Serializer):
    email_or_username = serializers.CharField()

class UserResetPasswordSerializer(serializers.Serializer):
    email_or_username = serializers.CharField()
    otp = serializers.CharField()
    new_password = serializers.CharField()