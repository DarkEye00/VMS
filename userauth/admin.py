from django.contrib import admin
from userauth.models import User, Visitor, EmailOTP
from .models import StaffCheckInOut

admin.site.register(User)
admin.site.register(Visitor)
admin.site.register(EmailOTP)


@admin.register(StaffCheckInOut)
class StaffCheckInOutAdmin(admin.ModelAdmin):
    list_display = ['name', 'id_no', 'department', 'time_in', 'time_out']
    search_fields = ['name', 'id_no', 'department']
