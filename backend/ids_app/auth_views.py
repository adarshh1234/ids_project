"""
ids_app/auth_views.py
=====================
Login and logout API endpoints using Django session authentication.
"""

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username', '')
        password = request.data.get('password', '')

        if not username or not password:
            return Response(
                {'error': 'Username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_staff or user.is_superuser:
                login(request, user)
                return Response({
                    'success': True,
                    'username': user.username,
                    'message': 'Login successful.',
                })
            else:
                return Response(
                    {'error': 'Access denied. Admin privileges required.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        else:
            return Response(
                {'error': 'Invalid username or password.'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'success': True, 'message': 'Logged out successfully.'})


class AuthStatusView(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            return Response({
                'authenticated': True,
                'username': request.user.username,
            })
        return Response({'authenticated': False})