"""
A Mailer is one tailored brief an organization subscribes to: what it covers
(profile), what's in it (sections + filters), how it reads (audience), and when
and to whom it goes (schedule + recipients). An org can have several, e.g. a
weekly Board brief and a daily SOC brief.
"""
import uuid
from datetime import timedelta
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db import models
from django.utils import timezone

from . import catalog


def default_sections():
    return list(catalog.DEFAULT_SECTIONS)


def default_sources():
    return list(catalog.SOURCE_KEYS)


class Mailer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("accounts.Organization", on_delete=models.CASCADE, related_name="mailers")
    name = models.CharField(max_length=120, default="Daily Threat Brief")
    is_active = models.BooleanField(default=True)

    # Profile — what matters to this audience
    industries = models.JSONField(default=list, blank=True)
    vendors = models.JSONField(default=list, blank=True)
    keywords = models.JSONField(default=list, blank=True)
    threat_actors = models.JSONField(default=list, blank=True)

    # Early-warning watchlist
    watch_names = models.JSONField(default=list, blank=True, help_text="Your company's names as attackers would write them")
    watch_domains = models.JSONField(default=list, blank=True, help_text="Your company's domains")
    suppliers = models.JSONField(default=list, blank=True, help_text='[{"name": ..., "domain": ...}] key suppliers & partners')

    # Content — what's in it
    audience = models.CharField(max_length=20, choices=catalog.AUDIENCES, default="executive")
    sections = models.JSONField(default=default_sections)
    min_risk = models.PositiveSmallIntegerField(default=50, help_text="Include items at or above this risk score (0-95) even without a profile match")
    exploited_only = models.BooleanField(default=False, help_text="Only include actively exploited items")
    sources = models.JSONField(default=default_sources)
    max_items = models.PositiveSmallIntegerField(default=10)

    # Delivery — when and to whom
    frequency = models.CharField(max_length=10, choices=catalog.FREQUENCIES, default="daily")
    send_weekday = models.PositiveSmallIntegerField(choices=catalog.WEEKDAYS, default=0)
    send_hour = models.PositiveSmallIntegerField(choices=catalog.HOURS, default=6)
    timezone = models.CharField(max_length=50, choices=catalog.TIMEZONES, default="America/New_York")
    send_to_all_members = models.BooleanField(default=True, help_text="Everyone in the org with email reports on")
    recipients = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name="mailers")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["organization__name", "name"]

    def __str__(self):
        return f"{self.organization.name} — {self.name}"

    # ---------------------------------------------------------------- schedule

    @property
    def tz(self):
        try:
            return ZoneInfo(self.timezone)
        except Exception:
            return ZoneInfo("America/New_York")

    def local_now(self, now=None):
        return (now or timezone.now()).astimezone(self.tz)

    def local_date(self, now=None):
        return self.local_now(now).date()

    @property
    def lookback(self) -> timedelta:
        if self.frequency == "weekly":
            return timedelta(days=7)
        return timedelta(hours=max(24, settings.LOOKBACK_HOURS))

    def is_due(self, now=None) -> bool:
        """Due once per period at/after the send hour; catches up if beat was down at that hour."""
        if not self.is_active:
            return False
        local = self.local_now(now)
        if local.hour < self.send_hour:
            return False
        if self.frequency == "weekly":
            if local.weekday() != self.send_weekday:
                return False
            period_start = local.date()
        else:
            period_start = local.date()
        return not self.reports.filter(report_date__gte=period_start, status__in=["completed", "processing"]).exists()

    def schedule_display(self) -> str:
        hour = dict(catalog.HOURS)[self.send_hour]
        if self.frequency == "weekly":
            return f"Weekly, {dict(catalog.WEEKDAYS)[self.send_weekday]} {hour} ({self.timezone})"
        return f"Daily, {hour} ({self.timezone})"

    # ------------------------------------------------------------- recipients

    def recipient_users(self):
        org_users = self.organization.users.filter(is_active=True)
        if self.send_to_all_members:
            return org_users.filter(email_reports=True)
        return self.recipients.filter(is_active=True, organization=self.organization)

    # ---------------------------------------------------------------- profile

    def match_terms(self):
        """[(label, term)] for every profile term; label is what we show as 'why you're seeing this'."""
        terms = []
        for v in self.vendors:
            terms += [(v, t) for t in catalog.VENDORS.get(v, [v])]
        for i in self.industries:
            terms += [(i, t) for t in catalog.INDUSTRIES.get(i, [i])]
        terms += [(k, k) for k in self.keywords]
        terms += [(a, a) for a in self.threat_actors]
        terms += [(k, k) for k in self.organization.keywords.filter(is_active=True).values_list("keyword", flat=True)]
        return [(label, t) for label, t in terms if t]

    def enabled_sections(self):
        return [s for s in self.sections if s in catalog.SECTION_LABELS]
