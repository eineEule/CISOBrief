from django.core.management.base import BaseCommand, CommandError

from apps.intelligence.tasks import fetch_kev_daily, fetch_rss_feeds
from apps.mailers.models import Mailer
from apps.mailers.tasks import send_report_emails
from apps.reports.utils import BriefBuilder


class Command(BaseCommand):
    help = "Build briefs now, synchronously (no Celery needed). Ignores each mailer's schedule."

    def add_arguments(self, parser):
        parser.add_argument("--org", help="Only mailers of this organization slug")
        parser.add_argument("--mailer", help="Only this mailer (UUID)")
        parser.add_argument("--skip-fetch", action="store_true", help="Don't pull feeds; use what's in the DB")
        parser.add_argument("--send", action="store_true", help="Also email recipients (Mailpit in dev)")
        parser.add_argument("--force", action="store_true", help="Rebuild even if today's brief is already done")

    def handle(self, *args, **opts):
        if not opts["skip_fetch"]:
            self.stdout.write(f"KEV: {fetch_kev_daily()} new items")
            self.stdout.write(f"RSS: {fetch_rss_feeds()} new items")

        mailers = Mailer.objects.filter(is_active=True, organization__is_active=True).select_related("organization")
        if opts["org"]:
            mailers = mailers.filter(organization__slug=opts["org"])
        if opts["mailer"]:
            mailers = mailers.filter(id=opts["mailer"])
        if not mailers.exists():
            raise CommandError("No matching active mailers. Create an Organization (it gets a default mailer) or build one at /mailers/.")

        for mailer in mailers:
            report = BriefBuilder(mailer).generate(force=opts["force"])
            self.stdout.write(self.style.SUCCESS(
                f"{mailer}: {report.status} — {report.items_included}/{report.items_analyzed} items — {report.headline}"
            ))
            if opts["send"] and report.is_ready:
                self.stdout.write(f"  sent to {send_report_emails(str(report.id))} recipient(s)")
