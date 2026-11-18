import logging

from celery import chord, group, shared_task
from django.utils import timezone

from apps.intelligence.tasks import fetch_kev_daily, fetch_rss_feeds

from .models import Mailer

logger = logging.getLogger(__name__)


@shared_task
def dispatch_mailers():
    """Hourly: find mailers due now (their own schedule/timezone), refresh data, then build each."""
    now = timezone.now()
    due = [str(m.id) for m in Mailer.objects.filter(is_active=True, organization__is_active=True).select_related("organization") if m.is_due(now)]
    if not due:
        logger.info("No mailers due")
        return 0
    logger.info("Dispatching %d due mailer(s)", len(due))
    chord(group(fetch_kev_daily.s(), fetch_rss_feeds.s()))(generate_mailers.si(due))
    return len(due)


@shared_task
def generate_mailers(mailer_ids):
    for mailer_id in mailer_ids:
        generate_mailer_report.delay(mailer_id)
    return len(mailer_ids)


@shared_task
def generate_mailer_report(mailer_id, force=False, send=True):
    from apps.reports.utils import BriefBuilder

    mailer = Mailer.objects.select_related("organization").get(id=mailer_id)
    report = BriefBuilder(mailer).generate(force=force)
    logger.info("Brief %s for %s: %s", report.id, mailer, report.status)
    if send and report.is_ready and not report.delivered_at:
        send_report_emails.delay(str(report.id), resend=force)
    return str(report.id)


@shared_task
def send_report_emails(report_id, resend=False):
    from apps.reports.models import Report, ReportDelivery
    from apps.reports.utils import send_report_email

    report = Report.objects.select_related("mailer", "organization").get(id=report_id)
    if not report.mailer_id:
        logger.warning("Report %s has no mailer; skipping send", report_id)
        return 0
    # "Send now" (resend=True) rebuilds today's report and mails it again, even to people who got the earlier version.
    already = set() if resend else set(ReportDelivery.objects.filter(report=report, email_sent=True).values_list("recipient_id", flat=True))
    sent = 0
    for user in report.mailer.recipient_users():
        if user.id in already:
            continue
        try:
            send_report_email(report, user)
            sent += 1
        except Exception as e:
            from apps.reports.mail import friendly_error

            logger.error("Error sending %s to %s: %s", report_id, user.email, friendly_error(e))
            ReportDelivery.objects.create(report=report, recipient=user, email_sent=False, error_message=friendly_error(e)[:2000])
    report.delivered_at = timezone.now()
    report.save(update_fields=["delivered_at"])
    return sent
