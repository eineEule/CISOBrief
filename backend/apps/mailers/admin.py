from django.contrib import admin

from .models import Mailer


@admin.register(Mailer)
class MailerAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "audience", "frequency", "send_hour", "timezone", "is_active"]
    list_filter = ["audience", "frequency", "is_active", "organization"]
    search_fields = ["name", "organization__name"]
    filter_horizontal = ["recipients"]
