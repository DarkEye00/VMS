from django.contrib import admin
from userauth.models import User, Visitor, EmailOTP

admin.site.register(User)
admin.site.register(Visitor)
admin.site.register(EmailOTP)
