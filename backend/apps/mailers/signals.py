from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.accounts.models import Organization


@receiver(post_save, sender=Organization)
def create_default_mailer(sender, instance, created, **kwargs):
    if created and not instance.mailers.exists():
        from .catalog import normalize_industries
        from .models import Mailer

        industries, extra = normalize_industries(instance.focus_industries)
        Mailer.objects.create(
            organization=instance,
            name="Daily Threat Brief",
            industries=industries,
            keywords=[k for k in (instance.custom_keywords or []) if k] + extra,
            threat_actors=[a for a in (instance.custom_threat_actors or []) if a],
        )
