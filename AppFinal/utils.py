import random
from datetime import datetime

from django.core.mail import send_mail
from .models import User, OneTimePassword
from django.conf import settings


def generateOtp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(1, 9))
    return otp


def send_code(email):
    Subject = 'One time passcode for Email verification'
    otp_code = generateOtp()
    user = User.objects.get(email=email)
    email_body = f'Hi {user.email}\n Your code check is: {otp_code}\n Be Careful Confidential Code, do not share!'
    from_email = settings.EMAIL_HOST_USER

    OneTimePassword.objects.create(user=user, code=otp_code)
    send_mail(Subject, email_body, from_email, [email])


def send_normal_email(data):
    send_mail(data['email_subject'], data['email_body'], settings.EMAIL_HOST_USER, [data['to_email']])

