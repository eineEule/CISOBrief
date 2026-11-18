"""Turn on the new Early warning section for existing mailers (placed right after the summary)."""
from django.db import migrations


def forwards(apps, schema_editor):
    Mailer = apps.get_model("mailers", "Mailer")
    for m in Mailer.objects.all():
        sections = list(m.sections or [])
        if "early_warning" in sections:
            continue
        pos = sections.index("summary") + 1 if "summary" in sections else 0
        sections.insert(pos, "early_warning")
        m.sections = sections
        m.save(update_fields=["sections"])


def backwards(apps, schema_editor):
    Mailer = apps.get_model("mailers", "Mailer")
    for m in Mailer.objects.all():
        m.sections = [s for s in (m.sections or []) if s != "early_warning"]
        m.save(update_fields=["sections"])


class Migration(migrations.Migration):
    dependencies = [("mailers", "0003_mailer_suppliers_mailer_watch_domains_and_more")]
    operations = [migrations.RunPython(forwards, backwards)]
