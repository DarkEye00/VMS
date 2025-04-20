import random
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from userauth.forms import UserRegistrationForm
from userauth.models import User, Group, Visitor, EmailOTP
from django.contrib import messages
from django.utils import timezone
from django.utils.timezone import now
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy

# Create your views here.+254102215152
def register(request):

    if request.method == "POST":
        form = UserRegistrationForm(request.POST or None)
        if form.is_valid():
            user = form.save()
            role = form.cleaned_data.get('role')

            if role == User.SECURITY:
                security_group, created = Group.objects.get_or_create(name='Security')
                user.groups.add(security_group)
                user.save()

                username = form.cleaned_data.get('username')
                messages.success(request, f"Account for {username} created successfully!")

                user = authenticate(username=form.cleaned_data.get("email"), password=form.cleaned_data.get('password1'))
    
                login(request, user)

                return redirect("userauth:security")
            else:
                if role == User.HOST:
                    host_group, created = Group.objects.get_or_create(name='Host')
                    user.groups.add(host_group)
                    user.save()

                    username = form.cleaned_data.get('username')
                    messages.success(request, f"Account for {username} created successfully!")

                    user = authenticate(username=form.cleaned_data.get("email"), password=form.cleaned_data.get('password1'))
                
                login(request, user)
                return redirect("userauth:host")
                
    else:
        form = UserRegistrationForm()
        
    context = {
            "form": form,
        }    
            
    return render(request, "register.html", context)

def login_view(request):

    def generate_otp():
        return str(random.randint(100000, 999999))
    
    # checking if a user is logged in
    
    if request.user.is_authenticated:
        messages.warning(request, "You are already logged in.")
        return redirect("userauth:security")  # Default to security for now

    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = authenticate(request, email=email, password=password)

        if user is not None:

            otp = generate_otp()
            EmailOTP.objects.update_or_create(user=user, defaults={"code":otp})

            send_mail(
                "Your OTP Code",
                f"Your Login verification code is: {otp}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False
            )

            request.session["pre_2fa_user_id"] = user.id

            return redirect("userauth:verify")

        else:
            messages.warning(request, "Invalid login credentials.")

    return render(request, "login.html")

def verify_otp(request):

    user_id = request.session.get("pre_2fa_user_id")
    if not user_id:
        return redirect("userauth:login")

    try:
        user = User.objects.get(id=user_id)
        otp_obj = EmailOTP.objects.get(user=user)
    except (User.DoesNotExist, EmailOTP.DoesNotExist):
        messages.error(request, "Session expired or invalid.")
        return redirect("userauth:login")

    if request.method == "POST":
        entered_code = request.POST.get("code")
        if otp_obj.code == entered_code and not otp_obj.is_expired():
            login(request, user)
            otp_obj.delete()
            del request.session["pre_2fa_user_id"]

            if user.groups.filter(name="Security").exists():
                messages.success(request, "Login was successful!")
                
                return redirect("userauth:security")
            elif user.groups.filter(name="Host").exists():
                return redirect("userauth:host")
            else:
                messages.warning(request, "No valid group assigned.")
                return redirect("userauth:login")
        else:
            messages.error(request, "Invalid or expired code.")

    return render(request, "verify_otp.html")

def logout(request):
    logout()

@login_required
def security_view(request):
    # Get Host users only
    try:
        host_group = Group.objects.get(name="Host")
        hosts = host_group.user_set.all()
    except Group.DoesNotExist:
        hosts = []

    # Handle visitor check-in submission
    if request.method == "POST":
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        reason = request.POST.get('reason')
        host_username = request.POST.get('host')

        try:
            host = User.objects.get(username=host_username)
            if host.groups.filter(name='Host').exists():
                Visitor.objects.create(
                    name=name,
                    phone=phone,
                    reason=reason,
                    host=host,
                    check_in=timezone.now(),
                    created_by=request.user
                )
                messages.success(request, f"{name} checked in successfully.")
                return redirect('userauth:security')
            else:
                messages.warning(request, "Selected user is not a valid host.")
        except User.DoesNotExist:
            messages.error(request, "Host does not exist.")

    visitors_in = Visitor.objects.filter(check_out__isnull=True)
    logs = Visitor.objects.order_by('-check_in')[:10]

    return render(request, 'security.html', {
        'visitors_in': visitors_in,
        'hosts': hosts,
        'logs': logs,
        'now': timezone.now(),
        
    })

def check_out(request, visitor_id):
    visitor = get_object_or_404(Visitor, id=visitor_id)
    if visitor.check_out is None:
        visitor.check_out = timezone.now()
        visitor.save()
        messages.success(request, f"{visitor.name} checked out successfully.")
    else:
        messages.warning(request, f"{visitor.name} has already checked out.")
    return redirect('userauth:security')

def host_view(request):
    # Placeholder for host view logic
    return render(request, 'host.html')

@login_required
def security_profile(request):
    user = request.user

    # Get today's date range
    today = now().date()
    visitors_today = Visitor.objects.filter(
        check_in__date=today,
        created_by=user  
    )
    visitor_count = visitors_today.count()

    context = {
        'user': user,
        'visitors_today': visitors_today,
        'visitor_count': visitor_count,
        'now': timezone.now(),
    }

    return render(request, 'sec_profile.html', context)

class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'password_change.html'  # your custom template
    success_url = reverse_lazy('userauth:profile')  # redirect to security profile

    def form_valid(self, form):
        messages.success(self.request, "Password changed successfully!")
        return super().form_valid(form)