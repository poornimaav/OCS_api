from django.urls import path, include, re_path
from . import views
from .views import *
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView



# router = DefaultRouter()
# router.register(r'courses', CourseListView, basename='course-list')

urlpatterns = [


    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    
    path('api-auth/', include('rest_framework.urls')),

    #register
    path('register/teacher/', TeacherRegisterAPIView.as_view(), name='teacher-register'),
    path('register/student/', StudentRegisterAPIView.as_view(), name='student-register'),

    #login and verify and logout
    path('verify-otp/', OTPVerificationAPIView.as_view(), name='otp-verification'),
    path('login/', views.LoginView.as_view(), name='login'),

    #logout
    path('logout/', LogoutView.as_view(), name='logout'),


    #teachers and student
    path('teachers/', TeachersListView.as_view(), name="teachers_list"),
    path('students/', StudentsListView.as_view(), name="students_list"),

    #courses
    path('courses/', CourseListView.as_view(), name='course-list'),
    path('courses/detail/<uuid:pk>/', CourseDetailView.as_view(), name='course-detail'),
    path('courses/create/', CourseCreateView.as_view(), name='course-create'),
    path('courses/update/<uuid:pk>/', CourseUpdateView.as_view(), name='update_course'),
    path('courses/delete/<uuid:pk>/', CourseDeleteView.as_view(), name='delete_course'),
    path('courses/course-search/', CourseSearchView.as_view(), name='course_search'),

    #contents
    # path('contents/', ContentListView.as_view(), name='content-list'),
    path('courses/contentcreate/<uuid:pk>/', ContentCreateView.as_view(), name='content-create'),
    path('courses/contents/<str:course_pk>/', CourseContentAPIView.as_view(), name='course-content-filter'),
    path('contents/update/<uuid:pk>/', ContentUpdateView.as_view(), name='update_course'),
    path('contents/delete/<uuid:pk>/', ContentDeleteView.as_view(), name='delete_course'),

    #switch roles
    path('switch_user/', SwitchUserRoleView.as_view(), name='switch_user_role'),

    #purchased courses
    path('courses/purchased/', PurchasedCourseListView.as_view(), name='course-list'),

    #paypal payment
    path('payment/', CreatePaypalPaymentView.as_view(), name=' paypal payment'),
    path('payment/success/', PaypalSuccessView.as_view(), name='payment-success'),
    path('payment/cancel/', PaypalCancelView.as_view(), name='payment-failure'),
    # path('payment/', CreatePaypalPaymentView.as_view(), name='create_paypal_payment'),

    #password-reset
    path('forget-password/', ForgetPasswordView.as_view(), name='forget_password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordView.as_view(), name='reset_password'),

    path('purchased-students/', views.PurchasedStudentsListView.as_view(), name='purchased_students_list'),
]