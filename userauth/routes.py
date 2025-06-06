from django.urls import path
from userauth import views
from django.contrib.auth import views as auth_views
from userauth.views import CustomPasswordChangeView  # Import the missing view
from django.contrib.auth.views import LogoutView  # Import LogoutView

app_name = "userauth"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("security_personnel/", views.security_view, name="security"),
    path("logout/", views.logout_view, name="logout"),
    path('check-out/<int:visitor_id>/', views.check_out, name='check_out'),
    path("host/", views.host_view, name="host"),
    path("verify/", views.verify_otp, name="verify"),
    path('security/profile/', views.security_profile, name='profile'),
    path('password-change/', CustomPasswordChangeView.as_view(), name='password_change'),
    path("export-csv/", views.export_visitors_csv, name="export_csv"),
    path('staff/check-in/', views.staff_check_in, name='staff_check_in'),
    path('staff/check-out/<int:staff_id>/', views.staff_check_out, name='staff_check_out'),
    path('staff/logs/', views.staff_logs, name='staff_logs'),
]