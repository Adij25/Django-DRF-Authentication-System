# Users/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import (
    UserRegistrationSerializer,
    UserVerificationSerializer,
    UserLoginSerializer,
    UserForgotPasswordSerializer,
    UserResetPasswordSerializer
)

class UserRegistrationAPIView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserVerificationAPIView(APIView):
    def get(self, request):
        return Response({"message": "This endpoint only supports POST method."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


    def post(self, request):
        serializer = UserVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email_or_username = serializer.validated_data['email_or_username']
            otp = serializer.validated_data['otp']
            
            try:
                user = User.objects.get(email=email_or_username)  
                if otp == '1234':  
                    return Response({'message': 'Verification successful'}, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            


class UserLoginAPIView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email_or_username = serializer.validated_data['email_or_username']
            otp = serializer.validated_data['otp']
            
            # Perform login logic here
            user = authenticate(username=email_or_username, password=otp)
            if user is not None:
                # User authenticated successfully
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh)
                }, status=status.HTTP_200_OK)
            else:
                # Invalid credentials
                return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            


class UserForgotPasswordAPIView(APIView):
    def post(self, request):
        serializer = UserForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email_or_username = serializer.validated_data['email_or_username']
            
            # Perform forgot password logic here
            try:
                user = User.objects.get(email=email_or_username)  
                # Generate password reset token
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                # Send password reset email or notify the user via another method
                # In this example, we'll print the reset token for demonstration purposes
                print(f"Password reset token for user {user.username}: {uid}-{token}")
                return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                # User not found
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            


class UserResetPasswordAPIView(APIView):
    def post(self, request):
        serializer = UserResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email_or_username = serializer.validated_data['email_or_username']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            
            # Perform reset password logic here
            try:
                user = User.objects.get(email=email_or_username)  
                uid = urlsafe_base64_decode(force_text(uidb64))
                if default_token_generator.check_token(user, token):
                    # Token is valid, reset password
                    user.set_password(new_password)
                    user.save()
                    return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
                else:
                    # Token is invalid
                    return Response({'message': 'Invalid reset token'}, status=status.HTTP_400_BAD_REQUEST)
            except (User.DoesNotExist, ValueError, TypeError):
                # User not found or invalid token format
                return Response({'message': 'Invalid reset token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            