from rest_framework.permissions import BasePermission
from .models import User_Roles


class IsStudent(BasePermission):
    def has_permission(self, request, view):
        try:
            user_role = User_Roles.objects.get(user=request.user)
            return user_role.role.name == 'student'
        except User_Roles.DoesNotExist:
            return False


class IsTeacher(BasePermission):
    def has_permission(self, request, view):
        try:
            user_role = User_Roles.objects.get(user=request.user)
            return user_role.role.name == 'teacher'
        except User_Roles.DoesNotExist:
            return False


class IsSpecialist(BasePermission):
    def has_permission(self, request, view):
        try:
            user_role = User_Roles.objects.get(user=request.user)
            return user_role.role.name == 'specialist'
        except User_Roles.DoesNotExist:
            return False


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_superuser
