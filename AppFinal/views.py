from rest_framework.exceptions import AuthenticationFailed
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
import time

from .serializers import TeacherRegisterSerializer, SpecialistRegisterSerializer, \
    AdminRegisterSerializer, LoginSerializer, ManageCourseSerializer, PasswordResetRequestSerializer, \
    SetNewPasswordSerializer, ValidateEmailSerializer, ResendOTPSerializer, CourseSerializer, \
    TeacherCourseAssignmentSerializer, TeacherSerializer, ProfileUpdateSerializer, UserInfoSerializer
from rest_framework.permissions import AllowAny
from .utils import send_code
from .models import OneTimePassword, User, Course, Badge, User_Roles, Teacher
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from .serializers import StudentRegisterSerializer


class RegisterStudentView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = StudentRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            student = serializer.save()
            user = serializer.data['user']
            email = user['email']
            send_code(email)  # Access the user's email through the related user object

            # Create login serializer instance with the user's credentials
            login_serializer = LoginSerializer(data={'email': email, 'password': request.data['password']})
            login_serializer.is_valid(raise_exception=True)
            login_data = login_serializer.validated_data

            # Return user data along with access and refresh tokens
            return Response({
                'data': serializer.data['user'],
                'degree': serializer.validated_data.get('degree'),
                'speciality': serializer.validated_data.get('speciality'),
                'university': serializer.validated_data.get('university'),
                'access_token': login_data['access_token'],
                'refresh_token': login_data['refresh_token']
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterTeacherView(GenericAPIView):
    serializer_class = TeacherRegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data['user']
            email = user['email']
            teacher_user = User.objects.get(email=email)
            send_code(email)
            return Response({
                'id': Teacher.objects.get(user=teacher_user).id,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterSpecialistView(GenericAPIView):
    serializer_class = SpecialistRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            specialist = serializer.data
            return Response({
                'data': specialist
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterAdminView(GenericAPIView):
    serializer_class = AdminRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            admin = serializer.data
            return Response({
                'data': admin
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ValidateEmailView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ValidateEmailSerializer(data=request.data)
        if serializer.is_valid():
            # Serializer validation passed, email is unique
            return Response({"message": "Email is valid."}, status=status.HTTP_200_OK)
        # Serializer validation failed, email is not unique
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendOTPView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            OneTimePassword.objects.get(user=user).delete()
            send_code(email)
            return Response({"message": "New OTP has been sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        email = request.data.get('email')

        # Check if both OTP and email are provided
        if not otp or not email:
            return Response({'message': 'Both OTP and email are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            user_code_obj = OneTimePassword.objects.get(code=otp, user=user)

            # Check if the user is already verified
            if user.is_verified:
                return Response({'message': 'User already verified'}, status=status.HTTP_400_BAD_REQUEST)

            # Mark the user as verified and generate tokens
            user.is_verified = True
            user.save()
            user_tokens = user.tokens()

            return Response({
                'message': 'Account email verified successfully',
                'email': user.email,
                'full_name': user.get_full_name(),
                'access_token': str(user_tokens.get('access')),
                'refresh_token': str(user_tokens.get('refresh'))
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'message': 'User with provided email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except OneTimePassword.DoesNotExist:
            return Response({'message': 'Invalid OTP code'}, status=status.HTTP_404_NOT_FOUND)


class LoginUserView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})

        # Check if email and password are provided
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response({'message': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed as e:
            return Response({'message': str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        # If authentication succeeds, serializer.data will contain the response data
        return Response(serializer.data, status=status.HTTP_200_OK)

    # class TestAuthentication(GenericAPIView):


#     permission_classes=[IsAuthenticated]
#     def get(self, request):
#         return Response({
#             'message': 'success'
#         }, status=status.HTTP_200_OK)


class ManageCourseView(GenericAPIView):
    serializer_class = ManageCourseSerializer

    def post(self, request):
        course_data = request.data
        serializer = self.serializer_class(data=course_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            course = serializer.data
            return Response({
                'data': course,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        pass


class PasswordResetRequestView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if not serializer.is_valid(raise_exception=True):
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'message': 'a link has been sent to your email to reset your password'
        }, status=status.HTTP_200_OK)


class PasswordResetConfirmView(GenericAPIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'token is invalid'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({
                'seccess': True,
                'message': 'credentials is valid',
                'token': token,
                'uidb64': uidb64
            }, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message': 'token is invalid'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [AllowAny]

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'password reset success'}, status=status.HTTP_200_OK)


class CourseList(APIView):
    permission_classes = [AllowAny]
    pagination_class = PageNumberPagination

    def get(self, request):
        paginator = self.pagination_class()
        courses = Course.objects.all()

        # Extract query parameters
        level_filter = request.query_params.get('level')
        degree_filter = request.query_params.get('degree')
        ordering = request.query_params.get('ordering', 'id')  # Default ordering by id
        order_direction = request.query_params.get('order_direction', 'asc')  # Default order direction is ascending

        # Apply filters
        if level_filter:
            courses = courses.filter(level=level_filter)
        if degree_filter:
            courses = courses.filter(degree=degree_filter)

        # Check if ordering field is valid
        if ordering not in ['id', 'title', 'degree', 'level']:
            return Response({"error": "Invalid ordering field."}, status=400)

        # Check if order direction is valid
        if order_direction not in ['asc', 'desc']:
            return Response({"error": "Invalid order direction. Use 'asc' or 'desc'."}, status=400)

        # Apply ordering
        if ordering == 'level':
            courses = sorted(courses, key=lambda x: (x.level_order(), x.title))
            if order_direction == 'desc':
                courses.reverse()
        else:
            if order_direction == 'desc':
                ordering = '-' + ordering
            courses = courses.order_by(ordering)

        # Paginate results
        if 'page' in request.query_params:
            result_page = paginator.paginate_queryset(courses, request)
            serializer = CourseSerializer(result_page, many=True)
            response_data = paginator.get_paginated_response(serializer.data)

            # Calculate the total number of pages
            total_pages = paginator.page.paginator.num_pages

            # Include the total number of pages in the response
            response_data.data['total_pages'] = total_pages

            return response_data
        else:
            # No pagination parameters included, return all courses
            serializer = CourseSerializer(courses, many=True)
            return Response(serializer.data)


class TeacherCourseAssignmentView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = TeacherCourseAssignmentSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        teacher = serializer.save()
        return Response(TeacherSerializer(teacher).data, status=status.HTTP_200_OK)


from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Student, Enroll_Course
from .serializers import StudentSerializer, EnrollCourseSerializer

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User_Roles, Student, Teacher, Course, Enroll_Course
from .serializers import EnrollCourseSerializer


class ProfileInfo(APIView):

    def get_image_url(self, instance, img_field_name):
        img_path = "file:///C:/Users/ADMI/Desktop/finale/FinalProject/"
        img_name = getattr(instance, img_field_name).name if getattr(instance, img_field_name).name else ""
        img_url = img_path + img_name if img_name else None
        return img_url

    def get(self, request, profile_id):
        try:
            user_role = User_Roles.objects.get(user_id=profile_id).role.name
            response_data = {}

            if user_role == "student":
                student = Student.objects.get(user_id=profile_id)
                enrolled_courses = Enroll_Course.objects.filter(student=student)
                enroll_course_data = EnrollCourseSerializer(enrolled_courses, many=True).data
                badges = Badge.objects.filter(students=student)
                badge_names = [badge.name for badge in badges]

                # Determine CanEdit based on user permission
                can_edit = request.user == student.user

                response_data = {
                    'FirstName': student.user.first_name,
                    'LastName': student.user.last_name,
                    'University': student.university,
                    'Speciality': student.speciality,
                    'Degree': student.degree,
                    'Score': student.score,
                    'Badges': badge_names,
                    'img': self.get_image_url(student, 'img'),
                    'DailyTimeSpent': student.daily_time_spent,
                    'WeeklyTimeSpent': student.weekly_time_spent,
                    'MonthlyTimeSpent': student.monthly_time_spent,
                    'EnrollCourse': enroll_course_data,
                    'CanEdit': can_edit,
                }

            elif user_role == "teacher":
                teacher = Teacher.objects.get(user_id=profile_id)
                courses = Course.objects.filter(teacher=teacher)
                course_data = [{'title': course.title} for course in courses]

                response_data = {
                    'FirstName': teacher.user.first_name,
                    'LastName': teacher.user.last_name,
                    'img': self.get_image_url(teacher, 'img'),
                    'courses': course_data,
                }
            elif user_role == "specialist":
                specialist = User.objects.get(user_id=profile_id)
                response_data = {
                    'FirstName': specialist.first_name,
                    'LastName': specialist.last_name,
                    'email': specialist.email,
                    'img': self.get_image_url(specialist, 'img'),
                }
            elif user_role == "admin":
                admin = User.objects.get(user_id=profile_id)
                response_data = {
                    'FirstName': admin.first_name,
                    'LastName': admin.last_name,
                    'email': admin.email,
                    'img': self.get_image_url(admin, 'img'),
                }
            return Response(response_data)
        except User_Roles.DoesNotExist:
            return Response({'error': 'User role not found'}, status=404)
        except (Student.DoesNotExist, Teacher.DoesNotExist):
            return Response({'error': 'Profile not found'}, status=404)


class UserDeleteView(APIView):

    def delete(self, request, profile_id):
        try:
            user = User.objects.get(user_id=profile_id)
            user.delete()
            return Response({"message": " User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetStudentImage(APIView):
    permission_classes = [AllowAny]

    def post(self, request, student_id):
        try:
            student = Student.objects.get(id=student_id)
        except Student.DoesNotExist:
            return Response({'error': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = StudentSerializer(student, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileUpdateAPIView(APIView):
    def put(self, request):
        print(request.user)
        user = request.user
        student = Student.objects.get(user=user)
        serializer = ProfileUpdateSerializer(student, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CourseDelete(APIView):
    permission_classes = [AllowAny]

    def delete(self, request, id):
        try:
            course = Course.objects.get(pk=id)
            course.delete()
            return Response({"message": "Course deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Course.DoesNotExist:
            return Response({"message": "Course not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UsersList(APIView):
    permission_classes = [AllowAny]
    pagination_class = PageNumberPagination

    def get(self, request):
        paginator = self.pagination_class()
        users = User.objects.all()

        # Extract query parameters
        speciality_filter = request.query_params.get('speciality')
        degree_filter = request.query_params.get('degree')
        ordering = request.query_params.get('ordering', 'id')  # Default ordering by id
        order_direction = request.query_params.get('order_direction', 'asc')  # Default order direction is ascending

        # Apply filters
        if speciality_filter:
            courses = users.filter(speciality=speciality_filter)
        if degree_filter:
            courses = users.filter(degree=degree_filter)

        # Check if ordering field is valid
        if ordering not in ['id', 'Name', 'degree', 'speciality']:
            return Response({"error": "Invalid ordering field."}, status=400)

        # Check if order direction is valid
        if order_direction not in ['asc', 'desc']:
            return Response({"error": "Invalid order direction. Use 'asc' or 'desc'."}, status=400)

        # Apply ordering
        if order_direction == 'desc':
            ordering = '-' + ordering
            courses = users.order_by(ordering)

        # Paginate results
        if 'page' in request.query_params:
            result_page = paginator.paginate_queryset(users, request)
            serializer = UserInfoSerializer(result_page, many=True)
            response_data = paginator.get_paginated_response(serializer.data)

            # Calculate the total number of pages
            total_pages = paginator.page.paginator.num_pages

            # Include the total number of pages in the response
            response_data.data['total_pages'] = total_pages

            return response_data
        else:
            # No pagination parameters included, return all courses
            serializer = UserInfoSerializer(users, many=True)
            return Response(serializer.data)
