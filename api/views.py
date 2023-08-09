from django.conf import settings
from .serializers import *
from .models import *
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import generics, status, viewsets
from rest_framework.views import APIView
from .mail import *
from .permissions import *
import json
import base64
import environ
import requests
import paypalrestsdk
from paypalrestsdk import Payment, configure


paypalrestsdk.configure({
    "mode": "sandbox", 
    "client_id": settings.PAYPAL_CLIENT_ID,
    "client_secret": settings.PAYPAL_CLIENT_SECRET,
})


# teacher registration
class TeacherRegisterAPIView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = TeacherRegSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "Teacher registered successfully. An OTP has been sent to your registered email, please verify your email", 
             "data": serializer.data,
             "status":status.HTTP_201_CREATED})
        
        except Exception as e:
            # Handle the exception and return an appropriate error response
            return Response(
                {
                    "message": "Failed to register teacher.",
                    "error": str(e),
                    "status":status.HTTP_400_BAD_REQUEST
            })

#student registration
class StudentRegisterAPIView(generics.CreateAPIView):
    
    permission_classes = [AllowAny]
    serializer_class = StudentRegSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "Student registered successfully. An OTP has been sent to your registered email, please verify your email", 
            "data": serializer.data,
            "status":status.HTTP_201_CREATED})
        
        except Exception as e:
            # Handle the exception and return an appropriate error response
            return Response(
                {
                    "message": "Failed to register student.",
                    "error": str(e),
                    "status":status.HTTP_400_BAD_REQUEST
            })


#otp verification
class OTPVerificationAPIView(generics.GenericAPIView):
    serializer_class = OTPVerificationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        
        # Check if OTP is correct
        otp = self.request.session.get('registration_otp')

        

        if not otp:
            return Response({"message": "OTP not found. Please register again.", "status":status.HTTP_400_BAD_REQUEST})
        
        if otp == validated_data['otp']:
            # Mark the user as verified
            user = User.objects.get(email=validated_data['email'])
            user.is_verified = True
            user.save()

            # Remove the OTP from the session or cache
            del self.request.session['registration_otp']

            return Response({"message": "OTP verification successful. You are now verified. Please Login to continue", "status":status.HTTP_200_OK})
        else:
            return Response({"message": "Invalid OTP. Verification failed.", "status":status.HTTP_400_BAD_REQUEST})
   


class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
    
        email = validated_data['email']
        password = validated_data['password']

        if not email or not password:
            return Response({"error": "Please provide both email and password to log in.",
                            "status":status.HTTP_400_BAD_REQUEST})

        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            # print(access_token.payload)
            if user.is_teacher:
                message = "Login successful as teacher."
            
            elif user.is_student:
                message = "Login successful as student."
            else:
                message = "Login successful."

            return Response({
                "message": message,
                "data": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
             "status":status.HTTP_200_OK })
        
        else:
            return Response({
                "message": "Invalid email or password. Please try again.",
             "status":status.HTTP_400_BAD_REQUEST})
        
#logout
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'message': 'Missing refresh_token', "status":status.HTTP_400_BAD_REQUEST})

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful', "status":status.HTTP_200_OK})
        except Exception as e:
            return Response({'message': 'Invalid refresh_token',"error": str(e), "status":status.HTTP_400_BAD_REQUEST})


# Teacher list
class TeachersListView(generics.ListAPIView):
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer
    permission_classes = [IsSuperuser, IsAuthenticated]

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            serializer = self.get_serializer(queryset, many=True)
            
            return Response(
                {
                    "message": "Teachers list retrieved successfully.",
                    "data": serializer.data,
                   "status":status.HTTP_200_OK}
            )
        except Exception as e:
            # Handle the exception and return an appropriate error response
            return Response(
                {
                    "message": "something went wrong.",
                    "error": str(e),
                "status":status.HTTP_500_INTERNAL_SERVER_ERROR
            })


#Student list
class StudentsListView(generics.ListAPIView):
    queryset  = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [IsSuperuser, IsAuthenticated]

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            serializer = self.get_serializer(queryset, many=True)
            
            return Response(
                {
                    "message": "Student list retrieved successfully.",
                    "data": serializer.data,
                   "status":status.HTTP_200_OK}
            )
        except Exception as e:
            # Handle the exception and return an appropriate error response
            return Response(
                {
                    "message": "something went wrong.",
                    "error": str(e),
                "status":status.HTTP_500_INTERNAL_SERVER_ERROR
            })

#course list
class CourseListView(generics.ListAPIView):
    # queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # If the user is a teacher, return the courses they created
        if user.is_authenticated and user.is_teacher:
            return Course.objects.filter(teacher=user)

        # If the user is a student, return all courses
        return Course.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
    
        if not queryset.exists():
            return Response({"message": "No courses available.", "status":status.HTTP_204_NO_CONTENT})

        serializer = self.get_serializer(queryset, many=True)
        return Response({"message": "Courses retrieved successfully.", "data": serializer.data, "status":status.HTTP_200_OK})


#course details

class CourseDetailView(generics.RetrieveAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseDetailSerializer
    lookup_url_kwarg = 'pk'
    permission_classes = [IsTeacherOrPurchasedStudent, IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['course_id'] = self.kwargs.get('pk')
        return context
        
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({"message": "Course details retrieved successfully.", "data": serializer.data, "status":status.HTTP_200_OK})

        except Course.DoesNotExist:
            return Response({"message": "Course not found.", "status":status.HTTP_404_NOT_FOUND})

        except Exception as e:
            # Handle any unexpected exceptions that might occur
            # Here, you may log the error for further investigation
            return Response({"message": "Something went wrong.", "error": str(e), "status":status.HTTP_500_INTERNAL_SERVER_ERROR})

#course create
class CourseCreateView(generics.CreateAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseCreateSerializer
    permission_classes = [IsTeacher, IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {"message": "Course created successfully.", 
            "data": serializer.data,
            "status":status.HTTP_201_CREATED
            
        })

    def perform_create(self, serializer):
        try:
        # Only verified teachers can create courses
            new_course = serializer.save(teacher=self.request.user)
            teacher_courses = Course.objects.filter(teacher=self.request.user).exclude(pk=new_course.pk)

            # Fetch students who purchased the teacher's previous courses
            students_purchased = Purchase.objects.filter(course__in=teacher_courses).values('student__email', 'student__username').distinct()

            # Send email to each student who purchased previous courses
            for purchase in students_purchased:
                student_email = purchase['student__email']
                student_username = purchase['student__username']
                teacher_name = self.request.user.get_full_name()  # Fetch the teacher's name
                send_course_update_email(new_course.title, teacher_name, student_username, student_email)

        except Exception as e:
            # If any error occurs during course creation or email sending, handle the exception
            # Here, you may log the error for further investigation
            return Response({"message": "Failed to create the course. Please try again later.",
                            "error": str(e),
                            "status":status.HTTP_500_INTERNAL_SERVER_ERROR})


#course update
class CourseUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseUpdateSerializer
    lookup_url_kwarg = 'pk'
    permission_classes = [IsOwnerTeacher, IsAuthenticated]

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response({"message": "Course updated successfully.", "data": serializer.data, "status":status.HTTP_200_OK})
        except Course.DoesNotExist:
            return Response({"message": "Course not found.", "status": status.HTTP_404_NOT_FOUND})
        except Exception as e:
            return Response({"message": "something went wrong", "error":str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR})


# course delete
class CourseDeleteView(generics.DestroyAPIView):
    queryset = Course.objects.all()
    lookup_url_kwarg = 'pk'
    permission_classes = [IsOwnerTeacher, IsAuthenticated]  # Set the lookup field to 'pk' to identify the course to delete

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response({"message": "Course deleted successfully.", "status": status.HTTP_204_NO_CONTENT})
        except Course.DoesNotExist:
            return Response({"message": "Course not found.", "status": status.HTTP_404_NOT_FOUND})
        except Exception as e:
            return Response({"message": "something went wrong", "error":str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR})


# course contents
class CourseContentAPIView(generics.ListAPIView):
    serializer_class = CourseContentSerializer
    permission_classes = [IsAuthenticated, IsTeacherOrPurchasedStudent]

    def get_queryset(self):
    
        course_pk = self.kwargs['course_pk']
        try:
            course = Course.objects.get(pk=course_pk)
        except Exception as e:
            return Response({"message": "Course not found.", "error":str(e), "status":status.HTTP_404_NOT_FOUND})
        
        if self.request.user.is_authenticated:

            if self.request.user.is_teacher and self.request.user == course.teacher and self.request.user.is_verified:
                # If the user is the teacher who created the course, return all contents
                contents=Content.objects.filter(course=course)
            
            elif self.request.user.is_student and self.request.user.is_verified:
                # If the user is a student, check if they purchased the course
                if course.purchase_set.filter(student=self.request.user, isPaid=True).exists():
                    # If the student purchased the course, return all contents
                    return Content.objects.filter(course=course)
        
        if not self.request.user.is_authenticated:
            return Response({"error": "Authentication credentials were not provided.", "status":status.HTTP_401_UNAUTHORIZED})
        


#content create
class ContentCreateView(generics.CreateAPIView):
    queryset = Course.objects.all()
    serializer_class = ContentCreateSerializer
    permission_classes = [IsCourseTeacher, IsAuthenticated]

    def create(self, request, *args, **kwargs):
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            course_id = self.kwargs.get('pk')
            print(course_id)
            course = get_object_or_404(self.queryset, pk=course_id)
            self.perform_create(serializer, course)
            headers = self.get_success_headers(serializer.data)
            return Response(
            {"message": "Content created successfully.",
             "data": serializer.data,
            "status":status.HTTP_201_CREATED
            })
                
        except Course.DoesNotExist:
            return Response({"message": "Course not found.", "status": status.HTTP_404_NOT_FOUND})
        except Exception as e:
            return Response({"message": "Course not found.", "error": str(e), "status": status.HTTP_404_NOT_FOUND})
    
    def perform_create(self, serializer, course):
        try:
            serializer.save(course=course)
            students_purchased = Purchase.objects.filter(course=course)

            # Send email to each student who purchased the course
            for purchase in students_purchased:
                student_username = purchase.student.username
                student_email = purchase.student.email
                send_content_update_email(course.title, student_email,student_username )
        except Exception as e:
            return Response({"message":"something went wrong", "error": str(e), "status":status.HTTP_500_INTERNAL_SERVER_ERROR})

# content update
class ContentUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Content.objects.all()
    serializer_class = ContentSerializer
    lookup_url_kwarg = 'pk' 
    permission_classes = [IsContentTeacher, IsAuthenticated] # Set the lookup field to 'pk' to identify the course to update
    # print(0)
    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except Exception as e:
            return Response({"message": "Content not found.", "error": str(e), "status": status.HTTP_404_NOT_FOUND})

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        return Response({"message": "Content updated successfully.",
         "data": serializer.data, 
         "status": status.HTTP_200_OK})

#content delete
class ContentDeleteView(generics.DestroyAPIView):
    queryset = Content.objects.all()
    lookup_url_kwarg = 'pk' 
    permission_classes = [IsContentTeacher, IsAuthenticated] # Set the lookup field to 'pk' to identify the course to delete

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response({"message": "Content deleted successfully.", "status": status.HTTP_204_NO_CONTENT})
        except Content.DoesNotExist:
            return Response({"message": "Content not found.", "status": status.HTTP_404_NOT_FOUND})
        except Exception as e:
            return Response({"message":"something went wrong", "error": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR})


#course search
class CourseSearchView(APIView):
    def get(self, request):
        query = request.GET.get('q', '')
        try:
            if not query:
                return Response({"message": "Please provide a search query.", "status":status.HTTP_400_BAD_REQUEST})

            courses = Course.objects.filter(
                Q(title__icontains=query) | Q(description__icontains=query)
            )
            serializer = CourseSerializer(courses, many=True)
            if len(serializer.data)==0:
                return Response({"message": "No courses found.", "status":status.HTTP_204_NO_CONTENT})
            
            return Response({"message":"course retrived successfully","data": serializer.data, "status":status.HTTP_200_OK})
        except Exception as e:
            return Response({"message":"something went wrong", "error": str(e), "status":status.HTTP_400_BAD_REQUEST})



#switch roles
class SwitchUserRoleView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = SwitchUserRoleSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        user = request.user
        if user.is_student:
            user.is_student = False
            user.is_teacher = True
            user.save()
            return Response({"message": "Role switched to Teacher.", "status":status.HTTP_200_OK})
        elif user.is_teacher:
            user.is_teacher = False
            user.is_student = True
            user.save()
            return Response({"message": "Role switched to Student.", "status":status.HTTP_200_OK})
        else:
            return Response({"message": "You are not a student or teacher.", "status":status.HTTP_400_BAD_REQUEST})

#purchased course list
class PurchasedCourseListView(generics.ListAPIView):
    serializer_class = PurchasedCourseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        # If the user is a student, return purchased courses with their contents
        purchased_courses = Course.objects.filter(purchase__student=user, purchase__isPaid=True)
        return purchased_courses

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({"message": "You have not purchased any courses.", "status":status.HTTP_204_NO_CONTENT})

        serializer = self.get_serializer(queryset, many=True)
        return Response({"message": "Purchased courses", "data": serializer.data, "status":status.HTTP_200_OK})


# paypal payment
class CreatePaypalPaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        course_id = request.data.get('course_id')
        student = request.user

    # Get the course and user details
        try:
            course = Course.objects.get(pk=course_id)
            # student = User.objects.get(pk=student_id)
            
        except Course.DoesNotExist:
            return Response({"error": "Invalid course"}, status=status.HTTP_404_NOT_FOUND)
        
        if Purchase.objects.filter(course=course, student=student, isPaid=True).exists():
            return Response({"error": "Course is already purchased.", "status":status.HTTP_400_BAD_REQUEST})
        
        amount = course.price
        # Set up the PayPal API credentials
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PAYPAL_API_ACCESS_TOKEN}",
        }

        # Create a PayPal payment
        # print("hello0")

        data = {
            "intent": "sale",
            "payer": {
                "payment_method": "paypal",
            },
            "transactions": [{
                "amount": {
                    "total": str(amount),
                    "currency": "USD",
                },
                "description": f"Payment for {course.title}",
            }],
            "redirect_urls": {
                "return_url": "http://127.0.0.1:8000/api/payment/success/",
                "cancel_url": "http://127.0.0.1:8000/api/payment/cancel/",
            },
        }

        try:
            response = requests.post(settings.PAYPAL_API_CREATE_PAYMENT_URL, json=data, headers=headers)
            response_data = response.json()
            # print(response_data)
            transaction_id = response_data.get('id')
            print(transaction_id)
            # Save the order details in your database
            purchase = Purchase.objects.create(
                course=course,
                student=student,
                teacher=course.teacher,
                transaction_id=response_data.get('id'),
                isPaid=False,  # Set isPaid to False initially
            )

            # Return the PayPal payment approval URL to the client
            approval_url = next(link['href'] for link in response_data['links'] if link['rel'] == 'approval_url')
            return Response({"approval_url": approval_url,  "transaction_id": response_data['id']})
    
        except Exception as e:
            return Response({"error": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR})

#payment success
class PaypalSuccessView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payment_id = request.data.get('payment_id')

        try:
            purchase = Purchase.objects.get(transaction_id=payment_id)
            purchase.isPaid = True
            purchase.save()

            course = purchase.course
            course_serializer = CourseSerializer(course)

            return Response({
                "message": "Payment successful, course purchased successfully!",
                "data": course_serializer.data,
                "status": status.HTTP_200_OK
            })

        except Purchase.DoesNotExist:
            return Response({"error": "Purchase not found", "status": status.HTTP_404_NOT_FOUND})
        
        except Exception as e:
            return Response({"message": "something went wrong", "error":str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR})

class PaypalCancelView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        return Response({"error": "Payment canceled or failed", "status": status.HTTP_400_BAD_REQUEST})

#forget password
class ForgetPasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ForgetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(email=serializer.validated_data["email"])
        serializer.send_reset_email(user, request)

        return Response({"message": "Password reset email sent.", "status":status.HTTP_200_OK})  


#password reset
class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            serializer = ResetPasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # Update user password
            password = serializer.validated_data["new_password"]
            user.set_password(password)
            user.save()

            return Response({"message": "Password reset successfully.", "status":status.HTTP_200_OK})
        else:
            return Response({"error": "Invalid reset link.", "status":status.HTTP_400_BAD_REQUEST})

class PurchasedStudentsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        teacher = request.user

        # Retrieve the courses created by the teacher
        courses = Course.objects.filter(teacher=teacher)
        if not courses.exists():
            return Response({"message": "You have not created any courses.", "status": status.HTTP_204_NO_CONTENT})
        
        # Retrieve the purchases for those courses
        purchases = Purchase.objects.filter(course__in=courses)
        if not purchases.exists():
            return Response({"message": "No students have purchased your courses.", "status": status.HTTP_204_NO_CONTENT})

        # Serialize the data to include student details
        serializer = PurchaseSerializer(purchases, many=True)

        return Response({"message": "List of purchased students", "data": serializer.data, "status": status.HTTP_200_OK})

