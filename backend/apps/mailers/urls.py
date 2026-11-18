from django.urls import path

from . import views

app_name = "mailers"
urlpatterns = [
    path("", views.mailer_list, name="list"),
    path("new/", views.mailer_create, name="create"),
    path("preview/", views.mailer_preview, name="preview_new"),
    path("<uuid:mailer_id>/", views.mailer_edit, name="edit"),
    path("<uuid:mailer_id>/preview/", views.mailer_preview, name="preview"),
    path("<uuid:mailer_id>/send/", views.mailer_send_now, name="send"),
    path("test-send/", views.mailer_test_send, name="test_send_new"),
    path("<uuid:mailer_id>/test-send/", views.mailer_test_send, name="test_send"),
]
