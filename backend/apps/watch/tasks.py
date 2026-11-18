import logging

from celery import shared_task

from . import collectors
from .targets import active_targets, targets_for

logger = logging.getLogger(__name__)


@shared_task
def collect_watch_frequent():
    """Every 6h: leak sites, community reports, malware hosting."""
    t = active_targets()
    return {"ransomlook": collectors.collect_ransomlook(t), "otx": collectors.collect_otx(t), "urlhaus": collectors.collect_urlhaus(t)}


@shared_task
def collect_watch_daily():
    """Daily: certificate lookalikes, infostealer exposure, likely-exploited vendor CVEs, EPSS enrichment."""
    t = active_targets()
    return {
        "crtsh": collectors.collect_crtsh(t), "hudsonrock": collectors.collect_hudsonrock(t),
        "likely_exploit": collectors.collect_likely_exploits(t), "epss_enriched": collectors.enrich_threat_items_epss(),
    }


@shared_task
def refresh_attack_groups():
    return collectors.refresh_attack_groups()


@shared_task
def scan_mailer(mailer_id):
    """Run every early-warning source for one mailer's watchlist (after it's created or edited)."""
    from apps.mailers.models import Mailer
    from .models import AttackGroup

    mailer = Mailer.objects.get(id=mailer_id)
    t = targets_for([mailer])
    result = {
        "ransomlook": collectors.collect_ransomlook(t, days=30), "otx": collectors.collect_otx(t),
        "urlhaus": collectors.collect_urlhaus(t), "crtsh": collectors.collect_crtsh(t),
        "hudsonrock": collectors.collect_hudsonrock(t), "likely_exploit": collectors.collect_likely_exploits(t),
    }
    if t.industries and not AttackGroup.objects.exists():
        result["attack_groups"] = collectors.refresh_attack_groups()
    logger.info("Scanned watchlist for %s: %s", mailer, result)
    return result
