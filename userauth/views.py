import random
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from userauth.forms import UserRegistrationForm
from userauth.models import Notification, User, Group, Visitor, EmailOTP
from django.contrib import messages
from django.utils import timezone
from django.utils.timezone import now
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from django.http import JsonResponse, HttpResponse
from datetime import datetime, timedelta
import csv
from .forms import StaffCheckInOutForm
from .models import StaffCheckInOut

# Create your views here.
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
    
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = authenticate(request, email=email, password=password)

        if user is not None:

            otp = generate_otp()
            EmailOTP.objects.update_or_create(user=user, defaults={"code":otp})

            send_mail(
                "Your OTP Code",
                f"Your Login verification code is: {otp}\n\ If you did not request this, please ignore this email.",
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

@login_required
def logout_view(request):
    logout(request)
    messages.success(request, "You have logged out")
    return redirect("userauth:login")

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

                    # Create a notification for the host
                send_mail(
                subject="New Visitor Checked In",
                message=f"Hello {host.username},\n\nYou have a new visitor: {name}.\nPhone: {phone}\nReason: {reason}\nChecked in at: {timezone.now().strftime('%d %b %Y, %I:%M %p')}",
                from_email=settings.DEFAULT_FROM_EMAIL,  # can be anything
                recipient_list=[host.email],
                fail_silently=False
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

@login_required
def check_out(request, visitor_id):
    visitor = get_object_or_404(Visitor, id=visitor_id)
    if visitor.check_out is None:
        visitor.check_out = timezone.now()
        visitor.save()
        messages.success(request, f"{visitor.name} checked out successfully.")
    else:
        messages.warning(request, f"{visitor.name} has already checked out.")
    return redirect('userauth:security')

@login_required
def host_view(request):
    today = timezone.now().date()
    now = timezone.now()

    # Get visitors for the host today
    visitors_today = Visitor.objects.filter(host=request.user, check_in__date=today)

     # Visitors checked in by this host (all-time)
    visitors_by_host = Visitor.objects.filter(host=request.user).order_by('-check_in')

    # Upcoming visitors (later today)
    upcoming_visitors = visitors_today.filter(check_in__gt=now)

    # Full visitor history for the host
    visitor_history = Visitor.objects.filter(host=request.user).order_by('-check_in')

    context = {
        'visitors_today': visitors_today,
        'upcoming_visitors': upcoming_visitors,
        'visitor_history': visitor_history,
        'visitors_by_host': visitors_by_host,
    }

    return render(request, 'host.html', context)

@login_required
def export_visitors_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=visitor_history.csv'

    writer = csv.writer(response)
    writer.writerow(['Name', 'Phone', 'Reason', 'Check-in', 'Check-out'])

    visitors = Visitor.objects.filter(host=request.user).order_by('-check_in')

    for v in visitors:
        check_in = v.check_in.strftime('%d %b %Y, %I:%M %p') if v.check_in else 'N/A'
        check_out = v.check_out.strftime('%d %b %Y, %I:%M %p') if v.check_out else 'Still inside'
        writer.writerow([v.name, v.phone, v.reason, check_in, check_out])

    return response

@login_required
def security_profile(request):
    user = request.user

    today = timezone.now().date()

    if user.role == 'host':
        visitors_today = Visitor.objects.filter(host=user, check_in__date=today)
        role = 'host'
    else:
        visitors_today = Visitor.objects.filter(created_by=user, check_in__date=today)
        role = 'security'

    context = {
        'user': user,
        'visitors_today': visitors_today,
        'visitor_count': visitors_today.count(),
        'now': timezone.now(),
        'role': role,
    }

    return render(request, 'profile.html', context)


class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'password_change.html'  # your custom template
    success_url = reverse_lazy('userauth:profile')  # redirect to security profile

    def form_valid(self, form):
        messages.success(self.request, "Password changed successfully!")
        return super().form_valid(form)

@login_required
def send_notification(request):
    # This would be triggered by some event in your app, e.g., user check-in
    notification = Notification.objects.create(
        user=request.user,  # Or any specific user
        message="New visitor check-in!"
    )
    return JsonResponse({'message': 'Notification sent!'})

@login_required
def staff_check_in(request):
    if request.method == 'POST':
        form = StaffCheckInOutForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('userauth:staff_logs')
    else:
        form = StaffCheckInOutForm()
    return render(request, 'staff.html', {'form': form})

@login_required
def staff_check_out(request, staff_id):
    staff = get_object_or_404(StaffCheckInOut, id=staff_id)

    if staff.time_out is None:
        staff.time_out = timezone.now()
        staff.save()
        messages.success(request, f"{staff.name} checked out successfully.")
    else:
        messages.warning(request, f"{staff.name} has already checked out.")
    return redirect('userauth:staff_logs')


@login_required
def staff_logs(request):
    logs = StaffCheckInOut.objects.all().order_by('-time_in')
    return render(request, 'staff_logs.html', {'logs': logs})