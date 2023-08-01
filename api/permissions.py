# permissions.py
from rest_framework.permissions import BasePermission
from rest_framework import generics, permissions
from .serializers import CourseDetailSerializer
from .models import Course



class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_superuser
        
class IsStudentAndVerified(BasePermission):
    def has_permission(self, request, view):
        # Check if the user is authenticated and a student
        is_student = request.user.is_authenticated and request.user.is_student
        # Check if the user is verified
        is_verified = request.user.is_authenticated and request.user.is_verified
        return is_student and is_verified



class IsTeacherOrPurchasedStudent(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Allow read access (GET, HEAD, OPTIONS) to the teacher who created the course
        if request.user.is_authenticated:
        
            if request.method in permissions.SAFE_METHODS and request.user == obj.teacher:
                return True

            # Allow write access (POST, PUT, PATCH, DELETE) to the teacher who created the course
            elif request.user.is_verified and request.user == obj.teacher:
                return True

            # Allow read access (GET, HEAD, OPTIONS) to purchased students
            elif request.user.is_verified and request.user.is_student:
                return obj.purchase_set.filter(student=request.user, isPaid=True).exists()
            
        return False

class IsTeacher(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            if request.user.is_teacher and request.user.is_verified:
                return True
        
            return False

class IsOwnerTeacher(BasePermission):
    def has_object_permission(self, request, view, obj):
        # if request.user.is_authenticated:
            if request.method in permissions.SAFE_METHODS and request.user == obj.teacher:
                return True

            if obj.teacher == request.user and request.user.is_verified:
                return True

            return False



class IsCourseTeacher(permissions.BasePermission):
    def has_object_permission(self, request, obj, view):
        # Allow access only to the teacher who created the course
        return request.user == obj.teacher and request.user.is_authenticated and request.user.is_teacher and request.user.is_verified

class IsContentTeacher(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Check if the requesting user is the content's teacher and is associated with the content's course
        return (
            obj.course.teacher == request.user and
            request.user.is_authenticated and
            request.user.is_teacher and
            request.user.is_verified
        )