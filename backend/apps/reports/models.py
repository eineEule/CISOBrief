"""
Report generation and delivery models
"""
from django.db import models
from django.utils import timezone
import uuid


class Report(models.Model):
    """Generated threat intelligence report"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='reports'
    )
    mailer = models.ForeignKey(
        'mailers.Mailer',
        on_delete=models.CASCADE,
        related_name='reports',
        null=True,
        blank=True
    )
    
    # Rendered brief data (sections, items, vendor watchlist...) used by web + email templates
    content = models.JSONField(default=dict, blank=True)
    
    # Report content
    headline = models.CharField(max_length=500)
    summary = models.TextField(blank=True)
    
    # Structured data
    top_themes = models.JSONField(default=list)
    active_attacks = models.JSONField(default=list)
    recommended_actions = models.JSONField(default=dict)
    limitations = models.JSONField(default=list)
    
    # Generated content
    html_content = models.TextField(blank=True)
    pdf_file = models.FileField(upload_to='reports/pdf/', null=True, blank=True)
    
    # Metadata
    report_date = models.DateField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Statistics
    items_analyzed = models.IntegerField(default=0)
    items_included = models.IntegerField(default=0)
    high_severity_count = models.IntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    generated_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    
    # AI generation
    ai_model_used = models.CharField(max_length=100, blank=True)
    generation_time_seconds = models.FloatField(null=True, blank=True)
    
    class Meta:
        ordering = ['-report_date', '-created_at']
        constraints = [
            models.UniqueConstraint(fields=['mailer', 'report_date'], name='uniq_report_per_mailer_per_day'),
        ]
        indexes = [
            models.Index(fields=['organization', '-report_date']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        name = self.mailer.name if self.mailer_id else 'Brief'
        return f"{self.organization.name} / {name} - {self.report_date}"
    
    @property
    def is_ready(self):
        return self.status == 'completed'
    
    @property
    def can_regenerate(self):
        age_hours = (timezone.now() - self.created_at).total_seconds() / 3600
        return age_hours > 24  # Can regenerate after 24 hours


class ReportDelivery(models.Model):
    """Track report delivery via email"""
    
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='deliveries')
    recipient = models.ForeignKey('accounts.User', on_delete=models.CASCADE)
    
    # Delivery
    email_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    
    # Engagement
    opened_at = models.DateTimeField(null=True, blank=True)
    clicked_at = models.DateTimeField(null=True, blank=True)
    
    # Error tracking
    error_message = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Report Deliveries'
    
    def __str__(self):
        return f"{self.report} → {self.recipient.email}"


class ReportFeedback(models.Model):
    """User feedback on report quality"""
    
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='feedback')
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE)
    
    # Rating
    RATING_CHOICES = [(i, str(i)) for i in range(1, 6)]
    rating = models.IntegerField(choices=RATING_CHOICES)
    
    # Feedback
    comment = models.TextField(blank=True)
    
    # Useful items
    helpful_items = models.JSONField(default=list)
    irrelevant_items = models.JSONField(default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['report', 'user']]
    
    def __str__(self):
        return f"{self.report} - {self.rating}⭐"
