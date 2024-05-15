from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User, Student, Teacher, Role, User_Roles, Course, Enroll_Course
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, smart_bytes
from django.urls import reverse
from .utils import send_normal_email, send_code
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=30, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=30, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword']


class StudentRegisterSerializer(serializers.ModelSerializer):
    # Define UserSerializer as a nested serializer
    user = UserSerializer()

    degree = serializers.CharField(max_length=30, required=True)
    university = serializers.CharField(max_length=100, required=True)
    speciality = serializers.CharField(max_length=100, required=True)
    courses_of_interest = serializers.CharField(max_length=255, required=False, allow_null=True)

    class Meta:
        model = Student
        fields = ['user', 'degree', 'university', 'speciality', 'courses_of_interest']

    def validate(self, attrs):
        # Access nested user data correctly
        user_data = attrs.get('user')
        password1 = user_data.get('password')
        password2 = user_data.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        # Extract nested user data and create user object
        user_data = validated_data.pop('user')
        email = user_data.pop('email')
        first_name = user_data.pop('first_name')
        last_name = user_data.pop('last_name')
        password = user_data.pop('password')

        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password
        )

        # Create student object and associate with user
        student = Student.objects.create(user=user, **validated_data)

        # Create role and user_role objects
        role = Role.objects.get_or_create(name='student')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        validated_data['user'] = user
        return validated_data


class TeacherRegisterSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    university = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = Teacher
        fields = ['user', 'university']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        # Extract nested user data and create user object
        user_data = validated_data.pop('user')
        email = user_data.pop('email')
        first_name = user_data.pop('first_name')
        last_name = user_data.pop('last_name')
        password = user_data.pop('password')

        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password
        )
        # Create teacher object and associate with user
        teacher = Teacher.objects.create(user=user, **validated_data)

        # Create role and user_role objects
        role = Role.objects.get_or_create(name='teacher')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        validated_data['user'] = user
        return validated_data


class SpecialistRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_superuser(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        user.save()
        role = Role.objects.get_or_create(name='specialist')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user


class AdminRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=15, min_length=8, write_only=True)
    confirmPassword = serializers.CharField(max_length=15, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirmPassword']

    def validate(self, attrs):
        password1 = attrs.get('password')
        password2 = attrs.get('confirmPassword')
        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_superuser(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        user.save()
        role = Role.objects.get_or_create(name='admin')[0]
        user_role = User_Roles.objects.create(user=user, role=role)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=100, write_only=True)
    password = serializers.CharField(max_length=70, write_only=True)
    message = serializers.CharField(read_only=True)
    username = serializers.EmailField(read_only=True)
    full_name = serializers.CharField(read_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    isVerified = serializers.BooleanField(read_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, username=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials. Please try again.')
        # if not user.is_verified:
        #     raise AuthenticationFailed('Email is not verified.')

        user_token = user.tokens()
        return {
            'message': 'success',
            'username': user.email,
            'full_name': user.get_full_name(),
            'access_token': str(user_token.get('access')),
            'refresh_token': str(user_token.get('refresh')),
            'isVerified': user.is_verified
        }


class ValidateEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['email']

    def validate_email(self, value):
        # Check if the email exists in the database
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value


class ResendOTPSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['email']

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email does not exist.")
        return value


class ManageCourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['title', 'description', 'degree', 'level', 'img_url']

    def create(self, validated_data):
        course = Course.objects.create(**validated_data)
        return course


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            site_domain = "localhost:5173/password_reset/"
            abslink = f"http://{site_domain}{uidb64}/{token}"
            email_body = 'Hello \n use the link below to reset your password \n' + abslink
            data = {
                'email_subject': 'Password Reset',
                'email_body': email_body,
                'to_email': user.email
            }
            send_normal_email(data)
        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=70, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=70, min_length=8, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        print(" -- user")
        try:
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            print(user_id, " user_id")
            user = User.objects.get(id=user_id)
            print(user, "  user")
            print(" password ", PasswordResetTokenGenerator().check_token(user, token))
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            if password != confirm_password:
                raise AuthenticationFailed('Password do not match')
            user.set_password(confirm_password)
            user.save()
            return user
        except Exception:
            return AuthenticationFailed('The reset link is invalid', 401)


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['id', 'title', 'description', 'degree', 'level', 'img_url', 'created_at', 'updated_at']


class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = ['id', 'university']


class TeacherCourseAssignmentSerializer(serializers.Serializer):
    teacher_id = serializers.IntegerField()
    course_names = serializers.CharField()

    def create(self, validated_data):
        teacher_id = validated_data.get('teacher_id')
        course_names = validated_data.get('course_names').split('#')

        teacher = Teacher.objects.get(pk=teacher_id)
        for course_name in course_names:
            # Find the course by name
            course = Course.objects.get(title=course_name)
            # Assign the course to the teacher
            teacher.course_set.add(course)

        return teacher


class UserIdSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()

    class Meta:
        model = User
        fields = ['id']


class StudentGoogleSerializer(serializers.ModelSerializer):
    user = UserIdSerializer()
    level = serializers.CharField(max_length=30, required=True)
    university = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = Student
        fields = ['user', 'degree', 'university']


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = ['user', 'university', 'degree', 'speciality', 'img']


class EnrollCourseSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='course.title')

    class Meta:
        model = Enroll_Course
        fields = ['title', 'score_earned', 'progress', 'updated_at']


class ProfileUpdateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')

    class Meta:
        model = Student
        fields = ['first_name', 'last_name', 'speciality', 'degree']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        user = instance.user
        user.first_name = user_data.get('first_name', user.first_name)
        user.last_name = user_data.get('last_name', user.last_name)
        user.save()

        instance.speciality = validated_data.get('speciality', instance.speciality)
        instance.degree = validated_data.get('degree', instance.degree)
        instance.save()

        return instance


class UserInfoSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'id', 'img', 'role', 'is_active', 'date_joined']

    def get_role(self, obj):
        user_role = User_Roles.objects.filter(user=obj).first()
        if user_role:
            return user_role.role.name  # Assuming 'name' is the field with the role name
        return None  # Or any default value you prefer
