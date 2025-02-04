from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import TokenGenerator, generate_token
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate, login, logout

# Create your views here.
import logging

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from django.contrib.auth.tokens import default_token_generator as generate_token
from django.contrib import messages
from django.shortcuts import render, redirect

def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']

        # Vérifier si les mots de passe correspondent
        if password != confirm_password:
            messages.warning(request, "Password is Not Matching")
            return render(request, 'signup.html')

        # Vérifier si l'email existe déjà
        try:
            if User.objects.get(username=email):
                messages.info(request, "Email is Taken")
                return render(request, 'signup.html')
        except User.DoesNotExist:
            pass

        # Créer l'utilisateur
        user = User.objects.create_user(email, email, password)
        user.is_active = False  # Utilisateur inactif au début
        user.save()

        # Générer l'email d'activation
        email_subject = "Activate Your Account"
        message = render_to_string('activate.html', {
            'user': user,
            'domain': 'c436-2c0f-f0f8-871-f100-f0e7-bfc6-553b-90b2.ngrok-free.app',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        import logging

        # Configurer le logger
        logger = logging.getLogger(__name__)

        try:
            send_mail(
                email_subject,
                message,
                'ddavidotis@gmail.com',
                [email],
                fail_silently=False,
                html_message=message
            )
            logger.info(f"Email envoyé à {email}")
        except Exception as e:
            # Si une erreur se produit, elle est capturée ici
            logger.error(f"Erreur lors de l'envoi de l'email: {str(e)}")
            messages.error(request, "Une erreur est survenue lors de l'envoi de l'email.")

        # Informer l'utilisateur que l'email a été envoyé
        messages.success(request, "Account created! Please check your email to activate your account.")
        return redirect('/auth/login/')

    return render(request, "signup.html")


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account Activated Successfully")
            return redirect('/auth/login')
        return render(request, 'activatefail.html')


def handlelogin(request):
    if request.method == "POST":
        username = request.POST['email']
        userpassword = request.POST['pass1']
        myuser = authenticate(username=username, password=userpassword)

        if myuser is not None:
            login(request, myuser)
            messages.success(request, "Login Success")
            return redirect('/')

        else:
            messages.error(request, "Invalid Credentials")
            return redirect('/auth/login')

    return render(request, 'login.html')


def handlelogout(request):
    logout(request)
    messages.info(request, "Logout Success")
    return redirect('/auth/login')


class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)

        if user.exists():
            email_subject = '[Reset Your Password]'
            message = render_to_string('reset-user-password.html', {
                'domain': 'c436-2c0f-f0f8-871-f100-f0e7-bfc6-553b-90b2.ngrok-free.app',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })

            # email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            # email_message.send()

            messages.info(request, f"WE HAVE SENT YOU AN EMAIL WITH INSTRUCTIONS ON HOW TO RESET THE PASSWORD {message} ")
            return render(request, 'request-reset-email.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid")
                return render(request, 'request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request, 'set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            messages.warning(request, "Password is Not Matching")
            return render(request, 'set-new-password.html', context)

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password Reset Success Please Login with New Password")
            return redirect('/auth/login/')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "Something Went Wrong")
            return render(request, 'set-new-password.html', context)

        return render(request, 'set-new-password.html', context)
