from django.shortcuts import render, redirect
from django.contrib.auth import logout, login

from core.utils.oauth2 import OAuth2
from .forms import UserChangeForm, RegisterForm, AccountFinishForm
from django.contrib.auth.forms import AuthenticationForm
from .models import Oauth2User, PawUser, GoogleSSOUser
from django.utils import translation
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .utils.google_sso import GoogleSSO


@login_required
def home_view(request):

    user_language = request.user.language
    translation.activate(user_language)
    res = redirect("all_tickets")
    res.set_cookie(settings.LANGUAGE_COOKIE_NAME, user_language)
    return res


def register_view(request):

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            PawUser.objects.create_user(
                username=form.cleaned_data.get("username"),
                email=form.cleaned_data.get("email"),
                password=form.cleaned_data.get("password")
            )
            return redirect("login")
    else:
        form = RegisterForm()

    return render(request, "core/register.html", {"form": form})


def login_view(request):

    auth_url = None
    oauth2_auth_url = None

    if settings.GOOGLE_OAUTH_ENABLED:
        google_sso = GoogleSSO()
        auth_url, state = google_sso.flow.authorization_url(prompt="consent")

        # Save data on Session
        if not request.session.session_key:
            request.session.create()
        request.session.set_expiry(60 * 1000)
        request.session["sso_state"] = state
        # request.session["sso_next_url"] = next_path
        request.session.save()
    
    if settings.OAUTH2_ENABLED:
        oauth_sso = OAuth2()
        oauth2_auth_url, state = oauth_sso.get_authorization_url()
        request.session["oauth_state"] = state
        request.session.save()

    if request.method == "POST":
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            return redirect("home")

    else:
        form = AuthenticationForm()

    return render(request, "core/login.html", {
        "form": form, 
        "google_sso_enabled": settings.GOOGLE_OAUTH_ENABLED, 
        "google_sso_auth_url": auth_url,
        "oauth2_enabled": settings.OAUTH2_ENABLED,
        "oauth2_auth_url": oauth2_auth_url,
        })

def oauth2_callback_view(request):

    if not settings.OAUTH2_ENABLED:
        return redirect("login")
    
    state = request.GET.get("state")

    if state != request.session.get("oauth_state"):
        return redirect("login")
    try:
        oauth_sso = OAuth2()
        _ = oauth_sso.fetch_token(request.GET.get("code"))
        user_info = oauth_sso.get_user_info()
    except Exception:
        return redirect("login")
            
    # Check if user already exists
    oauth2_user = Oauth2User.objects.filter(oauth2_id=user_info["sub"]).first()
    if oauth2_user:
        login(request, oauth2_user.paw_user)
        return redirect("home")
    
    # Create user if not exists
    unique_username = PawUser.objects.filter(username=user_info["nickname"]).exists()
    # TODO: Set up account finish form
    user, _ = PawUser.objects.get_or_create(email=user_info["email"], defaults={
        "username": user_info["nickname"] if not unique_username else user_info["email"],
        "display_name": user_info["name"],
        })

    Oauth2User.objects.create(paw_user=user, oauth2_id=user_info["sub"])
    
    login(request, user)
    return redirect("home")

def google_callback_view(request):

    if not settings.GOOGLE_OAUTH_ENABLED:
        return redirect("login")

    if request.method == "POST" and request.user.is_authenticated and "account_finish" in request.POST:
        form = AccountFinishForm(request.POST)
        if form.is_valid():
            request.user.username = form.cleaned_data["username"]
            request.user.save()
            return redirect("home")
        else:
            return render(request, "core/account_finish.html", {"form": form})
    else:
        google_sso = GoogleSSO()
        state = request.GET.get("state")
        code = request.GET.get("code")

        if state != request.session.get("sso_state"):
            return redirect("login")

        try:
            google_sso.flow.fetch_token(code=code)
            user_info = google_sso.get_user_info()
        except Exception:
            return redirect("login")

        user, created = PawUser.objects.get_or_create(email=user_info["email"], defaults={"username": user_info["email"]})

        if created:
            GoogleSSOUser.objects.create(paw_user=user, google_id=user_info["id"])

        login(request, user)
        if created or user.username == user.email:
            form = AccountFinishForm()
            return render(request, "core/account_finish.html", {"form": form})

    return redirect("home")


def logout_view(request):
    logout(request)
    return redirect("login")


@login_required
def settings_view(request):
    changed_user_language = False

    if request.method == "POST":
        form = UserChangeForm(request.POST, request.FILES)
        if form.is_valid():

            if form.cleaned_data["language"] != request.user.language:
                translation.activate(form.cleaned_data["language"])
                changed_user_language = True

            if not hasattr(request.user, 'googlessouser') and not hasattr(request.user, 'oauth2user'):
                request.user.email = form.cleaned_data["email"]

            request.user.language = form.cleaned_data["language"]
            request.user.telegram_username = form.cleaned_data["telegram_username"]
            request.user.use_darkmode = form.cleaned_data["use_darkmode"]
            request.user.receive_email_notifications = form.cleaned_data["receive_email_notifications"]
            if form.cleaned_data["profile_picture"]:
                request.user.profile_picture = form.cleaned_data["profile_picture"]
            request.user.save()
    else:
        form = UserChangeForm(initial={
            "email": request.user.email,
            "language": request.user.language,
            "telegram_username": request.user.telegram_username,
            "use_darkmode": request.user.use_darkmode,
            "receive_email_notifications": request.user.receive_email_notifications
        })

    res = render(request, "core/settings.html", {"form": form})
    if changed_user_language:
        res.set_cookie(settings.LANGUAGE_COOKIE_NAME, request.user.language)
    return res
