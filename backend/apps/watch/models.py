"""
Early-warning signals: the 'whisperings' that come before (or right after) an
attack on a watched company, supplier, industry or vendor.

Signals are stored per *target* (a domain, a company name, an industry or a
vendor), not per mailer, so many mailers watching the same supplier share one
lookup. Severity is decided at brief time, because the same leak-site post is
critical for the victim's own brief and 'high' for a customer of that victim.
"""
import uuid

from django.db import models

KINDS = [
    ("leak_site", "Named on a ransomware leak site"),
    ("malware_hosting", "Domain is hosting malware"),
    ("lookalike_domain", "Lookalike domain certificate issued"),
    ("infostealer", "Employee credentials stolen by infostealer malware"),
    ("threat_report", "Mentioned in a community threat report"),
    ("likely_exploit", "New CVE in your stack likely to be exploited soon"),
]
KIND_LABELS = dict(KINDS)

SOURCES = [
    ("ransomlook", "RansomLook"),
    ("crtsh", "crt.sh Certificate Transparency"),
    ("hudsonrock", "Hudson Rock"),
    ("otx", "AlienVault OTX"),
    ("urlhaus", "abuse.ch URLhaus"),
    ("epss", "FIRST EPSS + NVD"),
]
TARGET_TYPES = [("domain", "Domain"), ("name", "Company name"), ("industry", "Industry"), ("vendor", "Vendor")]


class WatchSignal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=30, choices=KINDS)
    source = models.CharField(max_length=20, choices=SOURCES)
    target = models.CharField(max_length=255, db_index=True, help_text="Lower-cased domain, name, industry or vendor")
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    title = models.CharField(max_length=500)
    detail = models.TextField(blank=True)
    url = models.URLField(max_length=500, blank=True)
    observed_at = models.DateTimeField(null=True, blank=True, help_text="When the source says it happened")
    discovered_at = models.DateTimeField(auto_now_add=True, db_index=True)
    fingerprint = models.CharField(max_length=64, unique=True)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-discovered_at"]
        indexes = [models.Index(fields=["target", "-discovered_at"])]

    def __str__(self):
        return f"[{self.get_kind_display()}] {self.target}: {self.title[:80]}"


class DomainExposure(models.Model):
    """Last Hudson Rock snapshot per domain, so we alert on *new* infections, not the same count every day."""
    domain = models.CharField(max_length=255, unique=True)
    employees = models.IntegerField(default=0)
    users = models.IntegerField(default=0)
    third_parties = models.IntegerField(default=0)
    last_employee_compromised = models.DateTimeField(null=True, blank=True)
    checked_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.domain}: {self.employees} employees"


class AttackGroup(models.Model):
    """MITRE ATT&CK intrusion sets, with the industries their descriptions say they target."""
    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=255)
    aliases = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    url = models.URLField(max_length=300, blank=True)
    industries = models.JSONField(default=list, blank=True)
    modified = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"

    def all_names(self):
        return [self.name] + [a for a in self.aliases if a and a != self.name]
