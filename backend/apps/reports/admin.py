from django.contrib import admin

from .models import Report, ReportDelivery, ReportFeedback


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["organization", "report_date", "status", "items_analyzed", "items_included", "high_severity_count", "delivered_at"]
    list_filter = ["status", "organization"]
    search_fields = ["headline", "organization__name"]
    readonly_fields = ["created_at", "generated_at", "delivered_at", "generation_time_seconds"]


@admin.register(ReportDelivery)
class ReportDeliveryAdmin(admin.ModelAdmin):
    list_display = ["report", "recipient", "email_sent", "sent_at", "retry_count"]
    list_filter = ["email_sent"]


@admin.register(ReportFeedback)
class ReportFeedbackAdmin(admin.ModelAdmin):
    list_display = ["report", "user", "rating", "created_at"]
    list_filter = ["rating"]
