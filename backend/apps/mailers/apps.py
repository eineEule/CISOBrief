from django.apps import AppConfig


class MailersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.mailers"

    def ready(self):
        from . import signals  # noqa: F401
