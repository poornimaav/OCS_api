from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model
from . mail import send_otp_email
import random
from django.contrib.auth import authenticate
import re
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from ocs.settings import EMAIL_HOST_USER
from django.utils.encoding import force_str, force_bytes
from rest_framework.response import Response
from rest_framework import status


class UserSerializer(serializers.ModelSerializer):
    # confirm_password = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'username', 'email', 'is_teacher', 'is_student','is_verified', 'password',  'confirm_password')
        extra_kwargs = {'password': {'write_only': True},
         'is_teacher': {'read_only': True},
         'is_student': {'read_only': True},
         'is_verified': {'read_only': True}
         }
    def validate_password(self, value):
        # Add custom password validation here
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not any(char.isalpha() for char in value):
            raise serializers.ValidationError("Password must contain at least one letter.")
        # Add more password validation rules as needed
        if not re.search(r'[@#$]', value):
            raise serializers.ValidationError("Password must contain at least one in these '@#$' symbols")
        return value
    def validate_email(self, value):
        # Check if a user with the given email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
        
    def validate_first_name(self, value):
        # Custom validation to check if first_name contains only alphabets
        if not value.isalpha():
            raise serializers.ValidationError("First name should contain only alphabets.")
        
        return value

    def validate_last_name(self, value):
        # Custom validation to check if last_name contains only alphabets
        if not value.isalpha():
            raise serializers.ValidationError("Last name should contain only alphabets.")
        
        return value


def generate_otp():
    return str(random.randint(100000, 999999))


class TeacherRegSerializer(serializers.ModelSerializer):
    user = UserSerializer()  # Use the UserSerializer for the nested user field

    class Meta:
        model = Teacher
        fields = ('user',)
    
    def create(self, validated_data):
        user_data = validated_data.pop('user')

        password = user_data.pop('password')
        confirm_password = user_data.pop('confirm_password', None)

        if password and confirm_password and password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")
        # user_data['is_teacher'] = True
        otp = generate_otp()
        try:
            send_otp_email(user_data['email'], otp)
        except Exception as e:
            raise serializers.ValidationError("Failed to send OTP email. Please try again later.")

        self.context['request'].session['registration_otp'] = otp
        try:
            user = User.objects.create_user(password=password, **user_data, is_teacher=True)
        except Exception as e:
            raise serializers.ValidationError("Failed to create user. Please try again later.")
        first_name=user_data.get('first_name')
        last_name=user_data.get('last_name')
        email=user_data.get('email')
        username=user_data.get('username')
        try:
            teacher = Teacher.objects.create(user=user, first_name=first_name, last_name=last_name,
                                             email=email, username=username, **validated_data)
        except Exception as e:
            # Rollback user creation if teacher creation fails
            user.delete()
            raise serializers.ValidationError("Failed to create teacher. Please try again later.")

        return teacher
        

class StudentRegSerializer(serializers.ModelSerializer):
    user = UserSerializer()  # Use the UserSerializer for the nested user field

    class Meta:
        model = Student
        fields = ('user',)


    def create(self, validated_data):
        user_data = validated_data.pop('user')

        password = user_data.pop('password')
        confirm_password = user_data.pop('confirm_password', None)

        if password and confirm_password and password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        otp = generate_otp()
        try:
            send_otp_email(user_data['email'], otp)
        except Exception as e:
            raise serializers.ValidationError("Failed to send OTP email. Please try again later.")

        self.context['request'].session['registration_otp'] = otp

        try:
            user = User.objects.create_user(password=password, **user_data, is_student=True)
        except Exception as e:
            raise serializers.ValidationError("Failed to create user. Please try again later.")
        
        first_name=user_data.get('first_name')
        last_name=user_data.get('last_name')
        email=user_data.get('email')
        username=user_data.get('username')
        try:
            student = Student.objects.create(user=user, first_name=first_name, last_name=last_name,
                                             email=email, username=username, **validated_data)
        except Exception as e:
            # Rollback user creation if student creation fails
            user.delete()
            raise serializers.ValidationError("Failed to create student. Please try again later.")
        
        return student


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=150)
    password = serializers.CharField(write_only=True)


class LogoutSerializer(serializers.Serializer):
    # You can include any additional fields in the serializer if needed.
    pass

class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = '__all__'

class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'

        
class CourseSerializer(serializers.ModelSerializer):
    teacher = serializers.SerializerMethodField()
    class Meta:
        model = Course
        exclude = ('contents',)
        
    def get_teacher(self, obj):
        return obj.teacher.username


class CourseUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        exclude= ('contents',)


class CourseCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        exclude = ('teacher','contents',)

class ContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = '__all__'

class CourseDetailSerializer(serializers.ModelSerializer):
    contents = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = '__all__'

    def get_contents(self, instance):
        course_id = self.context.get('course_id')
        contents = Content.objects.filter(course_id=course_id)
        return ContentSerializer(contents, many=True).data

class CourseContentSerializer(serializers.ModelSerializer):
    # contents = ContentSerializer(many=True, read_only=True)
    class Meta:
        model = Content
        fields = '__all__'

class ContentCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        exclude=('course',)


class PurchaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Purchase
        fields = '__all__'

class SwitchUserRoleSerializer(serializers.Serializer):
    pass


class PurchasedCourseSerializer(serializers.ModelSerializer):
    contents = ContentSerializer(many=True)

    class Meta:
        model = Course
        fields = '__all__'

    def to_representation(self, instance):
        # Filter contents based on the course ID
        contents = Content.objects.filter(course=instance)

        # Serialize the purchased course and its contents
        data = super().to_representation(instance)
        data['contents'] = ContentSerializer(contents, many=True).data

        return data



class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def send_reset_email(self, user, request):
        current_site = get_current_site(request)
        subject = "Reset your password"
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        reset_link = f"{current_site}/api/reset-password/{uid}/{token}/"
        message = f"Hello {user.username},\n\nWe received a request to reset your password. Please click the link below to reset it:\n\n{reset_link}\n\nIf you didn't request this password reset, you can ignore this email.\n\nBest regards,\nYour Website Team"
        
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid reset link.")

        if not default_token_generator.check_token(user, data['token']):
            raise serializers.ValidationError("Invalid reset link.")

        return data

    def save(self):
        uid = force_text(urlsafe_base64_decode(self.validated_data['uid']))
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user