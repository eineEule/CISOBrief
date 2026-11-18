"""
Give every existing organization a default mailer built from its org-level
keywords/industries, attach existing reports + processed items to it, and
remove the retired 'daily-brief-6am' beat entry (replaced by hourly dispatch).
"""
from django.db import migrations

from apps.mailers.catalog import normalize_industries

DEFAULT_SECTIONS = ["summary", "actions", "themes", "attacks", "vendors", "items"]
SOURCES = ["kev", "cisa_news", "hacker_news"]


def forwards(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    Mailer = apps.get_model("mailers", "Mailer")
    Report = apps.get_model("reports", "Report")
    ProcessedItem = apps.get_model("intelligence", "ProcessedItem")

    for org in Organization.objects.all():
        mailer = Mailer.objects.filter(organization=org).first()
        if mailer is None:
            industries, extra = normalize_industries(org.focus_industries)
            mailer = Mailer.objects.create(
                organization=org,
                name="Daily Threat Brief",
                industries=industries,
                keywords=list(org.custom_keywords or []) + extra,
                threat_actors=list(org.custom_threat_actors or []),
                sections=DEFAULT_SECTIONS,
                sources=SOURCES,
            )
        Report.objects.filter(organization=org, mailer__isnull=True).update(mailer=mailer)
        ProcessedItem.objects.filter(organization=org, mailer__isnull=True).update(mailer=mailer)

    try:
        PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
        PeriodicTask.objects.filter(name__in=["daily-brief-6am"]).delete()
    except LookupError:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("mailers", "0001_initial"),
        ("reports", "0002_alter_report_unique_together_report_content_and_more"),
        ("intelligence", "0002_alter_processeditem_unique_together_and_more"),
        ("accounts", "0001_initial"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
