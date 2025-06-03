from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, Group
from django.utils import timezone
from datetime import timedelta



# Create your models here.
class User(AbstractUser):
    """Creating a user in the model."""

    HOST = "Host"
    SECURITY = "Security"

    ROLE_CHOICES = [(SECURITY, "Security"), (HOST, "Host")]

    email = models.EmailField(unique=True, null=False)
    username = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=HOST)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return str(self.username)
    
class Visitor(models.Model):
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    reason = models.CharField(max_length=1000)
    host = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    check_in = models.DateTimeField(default=timezone.now)
    check_out = models.DateTimeField(null=True, blank=True)
    visitor_id = models.CharField(max_length=20, unique=True, blank=True, null=True, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='checked_in_visitors'
    )

    #signature = models.TextField(blank=True, null=True)  # Store base64 or filepath
    
    def __str__(self):
        return f"{self.name} - {self.check_in.strftime('%Y-%m-%d')}"
    
    def __str__(self):
        return f"{self.name} - {self.visitor_id}"

    def save(self, *args, **kwargs):
        if not self.visitor_id:
            last_visitor = Visitor.objects.exclude(visitor_id__isnull=True).order_by('-check_in').first()
            if last_visitor and last_visitor.visitor_id:
                try:
                    last_number = int(last_visitor.visitor_id.split('-')[-1])
                except ValueError:
                    last_number = 0
            else:
                last_number = 0

            next_badge_number = last_number + 1
            self.visitor_id = f"VIS-{next_badge_number:04d}"
        super().save(*args, **kwargs)

#OTP Model
class EmailOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)

    def __str__(self):
        return f"OTP for {self.user.username} - {self.code}"
    
class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.message

class StaffCheckInOut(models.Model):
    name = models.CharField(max_length=100)
    id_no = models.CharField(max_length=50)
    laptop_tag_no = models.CharField(max_length=50)
    department = models.CharField(max_length=100)
    time_in = models.DateTimeField(default=timezone.now)
    time_out = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.department}"