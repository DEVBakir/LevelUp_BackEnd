from django.urls import path
from .views import (RegisterStudentView, RegisterTeacherView, RegisterSpecialistView, RegisterAdminView,
                    LoginUserView, ManageCourseView,
                    PasswordResetRequestView,
                    ValidateEmailView,
                    ResendOTPView, TeacherCourseAssignmentView, VerifyUserEmail, ProfileInfo, SetStudentImage,
                    CourseList, ProfileUpdateAPIView, PasswordResetConfirmView, SetNewPasswordView, CourseDelete,
                    UsersList, UserDeleteView)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register/student/', RegisterStudentView.as_view(), name='signupStudent'),
    path('register/teacher/', RegisterTeacherView.as_view(), name='signupTeacher'),
    path('register/specialist/', RegisterSpecialistView.as_view(), name='registerSpecialist'),
    path('register/admin/', RegisterAdminView.as_view(), name='registerAdmin'),
    path('validate/email/', ValidateEmailView.as_view(), name='validateEmail'),
    path('resend/otp/', ResendOTPView.as_view(), name='resendOTP'),
    path('verify/otp/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('courses/', CourseList.as_view(), name='courses'),
    path('courses/assignement/', TeacherCourseAssignmentView.as_view(), name='teacherCourseAssignment'),
    # path('profile', TestAuthentication.as_view(), name='profile'),
    path('course/create', ManageCourseView.as_view(), name='create_course'),
    path('course/delete/<int:id>', CourseDelete.as_view(), name='delete_course'),
    path('password_reset', PasswordResetRequestView.as_view(), name='reset_password'),
    path('password_reset_confirm/<uidb64>/<token>', PasswordResetConfirmView.as_view(),
         name='reset_password_confirm'),
    path('set_new_password', SetNewPasswordView.as_view(), name='set_password'),
    # Test Token
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # HsBakirDev
    path('profile/<int:profile_id>/', ProfileInfo.as_view(), name='profile_info'),
    path('student/<int:student_id>/set_image/', SetStudentImage.as_view(), name='set_student_image'),
    path('api/profile/update/', ProfileUpdateAPIView.as_view(), name='profile-update'),
    path('usersList/', UsersList.as_view(), name='users_list'),
    path('user/delete/', UserDeleteView.as_view(), name='user_delete'),

]
