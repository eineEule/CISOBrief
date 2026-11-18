from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError

from apps.reports import mail


class Command(BaseCommand):
    help = "Send a test email through the SMTP settings in .env."

    def add_arguments(self, parser):
        parser.add_argument("--to", required=True, help="Where to send the test email")

    def handle(self, *args, **opts):
        self.stdout.write(f"Sending via {mail.describe()}")
        self.stdout.write(f"From: {settings.DEFAULT_FROM_EMAIL}  →  To: {opts['to']}")
        try:
            send_mail("CISO Brief: SMTP test", "If you can read this, CISO Brief can send email.",
                      settings.DEFAULT_FROM_EMAIL, [opts["to"]], fail_silently=False)
        except Exception as e:
            raise CommandError(f"Send failed: {mail.friendly_error(e)}")
        where = "Open http://localhost:8025 to see it (Mailpit)." if mail.is_dev_inbox() else "Check the inbox (and spam folder)."
        self.stdout.write(self.style.SUCCESS(f"Sent. {where}"))
