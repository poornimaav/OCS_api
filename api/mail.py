from django.core.mail import send_mail
from ocs.settings import EMAIL_HOST_USER

def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP is: {otp}'
    from_email = EMAIL_HOST_USER  # Replace with your sending email address
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)


def send_content_update_email(course_title, student_email, student_username):
    subject = f'New Content Added to Course: {course_title}'
    message = f'Hi {student_username}, \n\nNew content has been added to the course "{course_title}".\n\nLogin to your account to access the new content.\n\nThank you!'
    from_email = EMAIL_HOST_USER
    recipient_list = [student_email]

    send_mail(subject, message, from_email, recipient_list)

def send_course_update_email(course_title, teacher_name, student_username, student_email):
    subject = f'New Course Available: {course_title}'
    message = f'Hi  {student_username}, \n\nA new course "{course_title}" is now available from {teacher_name}. \n\nLogin to your account to access the new course.\n\nThank you!'
    from_email = EMAIL_HOST_USER
    recipient_list = [student_email]

    send_mail(subject, message, from_email, recipient_list)
