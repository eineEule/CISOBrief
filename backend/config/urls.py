from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from apps.accounts.views import onboarding

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("allauth.urls")),
    path("onboarding/", onboarding, name="onboarding"),
    path("dashboard/", RedirectView.as_view(pattern_name="dashboard:index", permanent=False)),
    path("reports/", include("apps.reports.urls")),
    path("mailers/", include("apps.mailers.urls")),
    path("", include("apps.dashboard.urls")),
]
