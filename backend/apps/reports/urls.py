from django.urls import path

from apps.dashboard import views

app_name = "reports"
urlpatterns = [
    path("<uuid:report_id>/", views.report_detail, name="detail"),
]
