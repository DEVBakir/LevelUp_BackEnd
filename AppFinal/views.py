from django.db.models import Q
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
import time

from rest_framework_simplejwt.tokens import RefreshToken

from .permissions import IsAdmin, IsSpecialist, IsStudent
from .serializers import TeacherRegisterSerializer, SpecialistRegisterSerializer, \
    AdminRegisterSerializer, LoginSerializer, ManageCourseSerializer, PasswordResetRequestSerializer, \
    SetNewPasswordSerializer, ValidateEmailSerializer, ResendOTPSerializer, CourseSerializer, \
    TeacherCourseAssignmentSerializer, TeacherSerializer, ProfileUpdateSerializer, UserInfoSerializer, \
    GetUserSerializer, LessonSerializer, SlideSerializer, CourseUpdateSerializer, EnrollCourseCreateSerializer, \
    UpdateUserSerializer, CourseSerializerForGet
from rest_framework.permissions import AllowAny
from .utils import send_code
from .models import OneTimePassword, User, Course, Badge, User_Roles, Teacher, Lesson, Slide, Role
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

from rest_framework.response import Response
from rest_framework import status, generics, viewsets
from rest_framework.generics import GenericAPIView
from .serializers import StudentRegisterSerializer


class RegisterStudentView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = StudentRegisterSerializer
    serializer_login = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = request.data.get('user')
            email = user['email']
            send_code(email)  # Access the user's email through the related user object
            # Auto login
            login_data = {
                'email': user['email'],
                'password': user['password']
            }
            login_serializer = self.serializer_login(data=login_data)
            if login_serializer.is_valid():
                return Response(login_serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
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
    permission_classes = [IsAdmin]
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
    permission_classes = [AllowAny]
    serializer_class = AdminRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(request.data)
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
    permission_classes = [AllowAny]
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


class SearchCourseView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ManageCourseSerializer

    def get(self, request):
        # Get the search keyword from URL parameters
        keyword = request.data.get('keysearch')
        print(f"Keyword: {keyword}")
        print(f"request: {request.data.get('keysearch')}")
        if keyword:
            # Use Q objects to search across multiple fields
            courses = Course.objects.filter(
                Q(title__icontains=keyword) |
                Q(description__icontains=keyword) |
                Q(degree__icontains=keyword) |
                Q(level__icontains=keyword),
                is_draft=False
            ).distinct()
        else:
            # If no keyword is provided, return all courses
            courses = Course.objects.filter(is_draft=False)

        # Serialize the results
        serializer = self.serializer_class(courses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
                'success': True,
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
    permission_classes = [AllowAny]

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
                    'DailyTimeSpent': student.daily_time_spent,
                    'WeeklyTimeSpent': student.weekly_time_spent,
                    'MonthlyTimeSpent': student.monthly_time_spent,
                    'EnrollCourse': enroll_course_data,
                    'Created': student.user.date_joined,
                    'CanEdit': can_edit,
                }

                if student.user.img:
                    # Include image URL in response data
                    response_data['img'] = student.user.img.url
                else:
                    # Set default placeholder image URL
                    response_data['img'] = '/images/defaultPersone.png'  # Adjust the path to your placeholder image

            elif user_role == "teacher":
                teacher = Teacher.objects.get(user_id=profile_id)
                courses = Course.objects.filter(teachers=teacher)
                course_data = [{'title': course.title} for course in courses]

                response_data = {
                    'FirstName': teacher.user.first_name,
                    'LastName': teacher.user.last_name,
                    'University': teacher.university,
                    'Courses': course_data,
                    'Created': teacher.user.date_joined
                }
                if teacher.user.img:
                    # Include image URL in response data
                    response_data['img'] = teacher.user.img.url
                else:
                    # Set default placeholder image URL
                    response_data['img'] = '/images/defaultPersone.png'

            return Response(response_data)
        except User_Roles.DoesNotExist:
            return Response({'error': 'User role not found'}, status=404)
        except (Student.DoesNotExist, Teacher.DoesNotExist):
            return Response({'error': 'Profile not found'}, status=404)


class UserDeleteView(APIView):
    permission_classes = [IsAdmin]

    def delete(self, request, profile_id):
        try:
            user = User.objects.get(id=profile_id)
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
    permission_classes = [IsSpecialist]

    def delete(self, request, pk):
        try:
            course = Course.objects.get(pk=pk)
            course.delete()
            return Response({"message": "Course deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Course.DoesNotExist:
            return Response({"message": "Course not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UsersList(APIView):
    permission_classes = [IsAdmin]
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


class GetUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = GetUserSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LessonCreateAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LessonSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LessonDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        try:
            return Lesson.objects.get(pk=pk)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found"}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        lesson = self.get_object(pk)
        serializer = LessonSerializer(lesson)
        return Response(serializer.data)


class LessonsByCourseAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, course_id):
        lessons = Lesson.objects.filter(course_id=course_id)
        serializer = LessonSerializer(lessons, many=True)
        return Response(serializer.data)

class LessonsByCourse1APIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, course_id):
        try:
            course = Course.objects.get(id=course_id)
            data = CourseSerializerForGet(course).data
            lessons = Lesson.objects.filter(course_id=course_id)
            serializer = LessonSerializer(lessons, many=True)
            return Response({
                'course': data,
                'lessons': serializer.data
            })
        except Course.DoesNotExist:
            return Response({'error': 'Course not found'}, status=status.HTTP_404_NOT_FOUND)

class LessonUpdateAPIView(APIView):
    permission_classes = [IsSpecialist]

    def put(self, request, pk):
        try:
            lesson = Lesson.objects.get(pk=pk)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = LessonSerializer(lesson, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LessonDeleteAPIView(APIView):
    permission_classes = [IsSpecialist]

    def delete(self, request, pk):
        try:
            lesson = Lesson.objects.get(pk=pk)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found"}, status=status.HTTP_404_NOT_FOUND)

        lesson.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class SlideCreateAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SlideSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SlideDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        try:
            return Slide.objects.get(pk=pk)
        except Slide.DoesNotExist:
            return Response({"error": "Slide not found"}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        slide = self.get_object(pk)
        serializer = SlideSerializer(slide)
        return Response(serializer.data)


class SlidesByLessonAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, lesson_id):
        slides = Slide.objects.filter(lesson_id=lesson_id)
        serializer = SlideSerializer(slides, many=True)
        return Response(serializer.data)


class SlideUpdateAPIView(APIView):
    permission_classes = [IsSpecialist]

    def put(self, request, pk):
        try:
            slide = Slide.objects.get(pk=pk)
        except Slide.DoesNotExist:
            return Response({"error": "Slide not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = SlideSerializer(slide, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SlideDeleteAPIView(APIView):
    permission_classes = [IsSpecialist]

    def delete(self, request, pk):
        try:
            slide = Slide.objects.get(pk=pk)
        except Slide.DoesNotExist:
            return Response({"error": "Slide not found"}, status=status.HTTP_404_NOT_FOUND)

        slide.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CourseUpdateView(APIView):
    permission_classes = [IsSpecialist]

    def put(self, request, pk):
        try:
            course = Course.objects.get(pk=pk)
        except Course.DoesNotExist:
            return Response({"error": "Course not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CourseUpdateSerializer(course, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EnrollCourseCreateAPIView(APIView):
    permission_classes = [IsStudent]

    def post(self, request):
        serializer = EnrollCourseCreateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EnrollCourseUpdateAPIView(APIView):
    permission_classes = [IsStudent]

    def put(self, request, pk):
        try:
            enrolled = Enroll_Course.objects.get(pk=pk)
        except Slide.DoesNotExist:
            return Response({"error": "Enrolled not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = SlideSerializer(enrolled, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CourseCreateAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data

        # Create Course instance
        course_data = {
            'title': data.get('title'),
            'description': data.get('description'),
            'img_url': data.get('img_url'),
            'degree': data.get('degree'),
            'level': data.get('level'),
            'category': data.get('category'),
            'is_draft': False  # Assuming it's not a draft upon creation
        }
        # Creat Course
        course_serializer = CourseSerializer(data=course_data)
        course_serializer.is_valid(raise_exception=True)
        course = course_serializer.save()
        print(course.id)
        # Create Lessons and associated Slides
        lessons_data = data.get('lessons', [])
        for lesson_data in lessons_data:
            slides_data = lesson_data.pop('slides', [])

            # Create Lesson instance
            lesson_data['course'] = course.id  # Link lesson to the course
            lesson_serializer = LessonSerializer(data=lesson_data)
            lesson_serializer.is_valid(raise_exception=True)
            lesson = lesson_serializer.save()
            print(lesson.id)

            # Create Slides for this Lesson
            for slide_data in slides_data:
                slide_data['lesson'] = lesson.id  # Link slide to the lesson
                slide_serializer = SlideSerializer(data=slide_data)
                slide_serializer.is_valid(raise_exception=True)
                slide = slide_serializer.save()
                print(slide.id)

        return Response(course_serializer.data, status=status.HTTP_201_CREATED)


class ModifyUserView(APIView):
    permission_classes = [AllowAny]

    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = UpdateUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            if request.data.get('role'):
                print("test2")
                if request.data.get('role') != User_Roles.objects.get(user=user).role.name:
                    role = Role.objects.get(name=request.data.get('role'))
                    user_role = User_Roles.objects.get(user=user)
                    user_role.role = role
                    user_role.save()
                    print("tesst2")
            #print(User_Roles.objects.filter(user=user).first())

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
