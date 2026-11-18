import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

celery_app = Celery("ciso_brief")
celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.autodiscover_tasks()

# Synced into django_celery_beat's DB tables on beat startup; editable in /admin afterwards.
celery_app.conf.beat_schedule = {
    "collect-every-4h": {
        "task": "apps.intelligence.tasks.collect_all",
        "schedule": crontab(minute=15, hour="*/4"),
    },
    "dispatch-mailers-hourly": {
        # Each Mailer has its own frequency / send hour / timezone; this just checks who's due.
        "task": "apps.mailers.tasks.dispatch_mailers",
        "schedule": crontab(minute=0),
    },
    "early-warning-6h": {
        "task": "apps.watch.tasks.collect_watch_frequent",
        "schedule": crontab(minute=30, hour="*/6"),
    },
    "early-warning-daily": {
        "task": "apps.watch.tasks.collect_watch_daily",
        "schedule": crontab(minute=40, hour=3),
    },
    "attack-groups-weekly": {
        "task": "apps.watch.tasks.refresh_attack_groups",
        "schedule": crontab(minute=10, hour=3, day_of_week=0),
    },
    "weekly-cleanup": {
        "task": "apps.intelligence.tasks.cleanup_old_data",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),
    },
}
