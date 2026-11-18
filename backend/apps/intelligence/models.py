"""
Threat Intelligence data models
"""
from django.db import models
from django.utils import timezone
import uuid


class ThreatItem(models.Model):
    """Individual threat intelligence item from various sources"""
    
    SOURCE_CHOICES = [
        ('kev', 'CISA KEV'),
        ('cisa_news', 'CISA News'),
        ('hacker_news', 'The Hacker News'),
        ('nvd', 'NVD'),
        ('custom', 'Custom Feed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Core fields
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES)
    title = models.TextField()
    url = models.URLField(max_length=500)
    description = models.TextField(blank=True)
    
    # CVE info (if applicable)
    cve_id = models.CharField(max_length=50, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    epss = models.FloatField(null=True, blank=True, help_text="FIRST EPSS probability of exploitation in 30 days")
    epss_percentile = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=20, blank=True)
    
    # Threat intelligence
    threat_actor = models.CharField(max_length=255, blank=True)
    is_actively_exploited = models.BooleanField(default=False)
    is_zero_day = models.BooleanField(default=False)
    is_ransomware = models.BooleanField(default=False)
    
    # Relevance scoring
    risk_score = models.IntegerField(default=0)  # 0-100
    relevance_score = models.IntegerField(default=0)  # 0-100
    
    # Raw data
    raw_data = models.JSONField(default=dict)
    
    # Timestamps
    published_at = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Deduplication
    content_hash = models.CharField(max_length=64, unique=True, db_index=True)
    
    class Meta:
        ordering = ['-published_at', '-discovered_at']
        indexes = [
            models.Index(fields=['-published_at']),
            models.Index(fields=['source', '-published_at']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['is_actively_exploited']),
        ]
    
    def __str__(self):
        return f"[{self.source}] {self.title[:100]}"
    
    @property
    def is_high_severity(self):
        return self.risk_score >= 70
    
    @property
    def age_days(self):
        if not self.published_at:
            return 0
        delta = timezone.now() - self.published_at
        return delta.days


class ProcessedItem(models.Model):
    """Track which items have been included in reports"""
    
    threat_item = models.ForeignKey(ThreatItem, on_delete=models.CASCADE)
    organization = models.ForeignKey('accounts.Organization', on_delete=models.CASCADE)
    mailer = models.ForeignKey('mailers.Mailer', on_delete=models.CASCADE, null=True, blank=True)
    
    included_in_report = models.ForeignKey(
        'reports.Report',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    
    processed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['threat_item', 'mailer']]
        indexes = [
            models.Index(fields=['organization', '-processed_at']),
        ]


class CustomKeyword(models.Model):
    """Organization-specific keywords for relevance filtering"""
    
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='keywords'
    )
    
    keyword = models.CharField(max_length=255)
    weight = models.IntegerField(default=10)  # How much to boost relevance
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['organization', 'keyword']]
    
    def __str__(self):
        return f"{self.organization.name}: {self.keyword}"


class ThreatActor(models.Model):
    """Known threat actors for tracking and attribution"""
    
    name = models.CharField(max_length=255, unique=True)
    aliases = models.JSONField(default=list)
    
    TYPE_CHOICES = [
        ('apt', 'Advanced Persistent Threat'),
        ('ransomware', 'Ransomware Group'),
        ('cybercrime', 'Cybercrime'),
        ('hacktivist', 'Hacktivist'),
        ('unknown', 'Unknown'),
    ]
    actor_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    
    country_origin = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    
    # Targeting
    typical_targets = models.JSONField(default=list)
    typical_ttps = models.JSONField(default=list)  # Tactics, Techniques, Procedures
    
    # Metadata
    first_seen = models.DateField(null=True, blank=True)
    last_activity = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
