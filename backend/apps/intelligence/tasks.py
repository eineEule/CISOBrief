"""
Celery tasks for threat intelligence collection and report generation.

Collection: fetch_kev_daily + fetch_rss_feeds, every 4 hours (collect_all).
Briefs: apps.mailers.tasks.dispatch_mailers runs hourly and builds each Mailer
that is due (its own frequency / hour / timezone), collecting fresh data first.
"""
import hashlib
import logging
import re
from functools import lru_cache
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Dict, List

import feedparser
import requests
from celery import shared_task
from django.conf import settings
from django.utils import timezone

from apps.accounts.models import Organization
from apps.intelligence.models import ThreatActor, ThreatItem
from apps.reports.models import Report

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_FEEDS = [
    ("https://www.cisa.gov/news.xml", "cisa_news"),
    ("https://feeds.feedburner.com/TheHackersNews", "hacker_news"),
]
HTTP_HEADERS = {"User-Agent": "CISO-Brief/1.0 (+threat-intel digest)"}

# Generic enterprise keywords. Industry-specific terms (construction, ICS, etc.)
# belong in each Organization's custom_keywords / focus_industries.
DEFAULT_KEYWORDS = [
    "microsoft", "windows", "azure", "entra", "exchange", "office", "defender",
    "apple", "macos", "ios", "cisco", "fortinet", "palo alto", "ivanti", "citrix",
    "vpn", "iam", "sso", "mfa", "okta",
    "ransomware", "zero-day", "0-day",
    "remote code execution", "actively exploited",
]

EXPLOITED_PHRASES = [
    "actively exploited", "exploited in the wild", "under active exploitation",
    "active exploitation", "exploited in attacks", "being exploited",
]

GENERIC_ACTOR_INDICATORS = [
    "lazarus", "sandworm", "volt typhoon", "salt typhoon", "apt28", "apt29",
    "lockbit", "alphv", "blackcat", "cl0p", "scattered spider", "akira",
]


@lru_cache(maxsize=4096)
def _kw_regex(keyword: str) -> re.Pattern:
    """Whole-word / whole-phrase match, so 'rce' doesn't hit 'source' and 'ics' doesn't hit 'politics'."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(keyword.lower()) + r"(?![a-z0-9])")


def has_keyword(text: str, keyword: str) -> bool:
    return bool(keyword) and bool(_kw_regex(keyword).search((text or "").lower()))


def generate_content_hash(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode())
        h.update(b"\x00")
    return h.hexdigest()


def calculate_risk_score(item_data: Dict) -> int:
    """Heuristic 0-95 risk score from title keywords. KEV items are always 95."""
    if item_data.get("source") == "kev":
        return 95
    title = item_data.get("title", "")
    score = 40
    if has_keyword(title, "ransomware"):
        score += 30
    if has_keyword(title, "zero-day") or has_keyword(title, "0-day"):
        score += 25
    if any(has_keyword(title, p) for p in EXPLOITED_PHRASES):
        score += 25
    if has_keyword(title, "critical"):
        score += 20
    if has_keyword(title, "remote code execution") or has_keyword(title, "rce"):
        score += 15
    return min(score, 95)


def is_actively_exploited(text: str) -> bool:
    return any(has_keyword(text, p) for p in EXPLOITED_PHRASES)


def identify_threat_actor(text: str) -> str:
    for actor in ThreatActor.objects.filter(is_active=True):
        if has_keyword(text, actor.name) or any(has_keyword(text, a) for a in actor.aliases):
            return actor.name
    for indicator in GENERIC_ACTOR_INDICATORS:
        if has_keyword(text, indicator):
            return indicator.title()
    return "Unknown / Opportunistic"


# ---------------------------------------------------------------- collection

@shared_task
def fetch_kev_daily():
    """
    Fetch CISA KEV entries added within the lookback window.

    KEV only records a date (YYYY-MM-DD) per entry, so we compare dates, not
    timestamps, and look back at least two calendar days. Dedup by content hash
    makes re-seeing an entry harmless.
    """
    logger.info("Fetching CISA KEV data...")
    try:
        response = requests.get(CISA_KEV_URL, timeout=30, headers=HTTP_HEADERS)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.error("Error fetching KEV: %s", e)
        return 0

    lookback_days = max(2, settings.LOOKBACK_HOURS // 24 + 1)
    cutoff_date = timezone.localdate() - timedelta(days=lookback_days)
    new_items = 0

    for vuln in data.get("vulnerabilities", []):
        try:
            date_added = datetime.fromisoformat(vuln["dateAdded"]).date()
            if date_added < cutoff_date:
                continue
            cve_id = vuln.get("cveID", "")
            content_hash = generate_content_hash("KEV", cve_id)
            if ThreatItem.objects.filter(content_hash=content_hash).exists():
                continue
            ThreatItem.objects.create(
                source="kev",
                title=f"{cve_id} — {vuln.get('vulnerabilityName', '')}",
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                description=vuln.get("shortDescription", ""),
                cve_id=cve_id,
                is_actively_exploited=True,
                is_ransomware=vuln.get("knownRansomwareCampaignUse", "").lower() == "known",
                risk_score=95,
                published_at=timezone.make_aware(datetime.combine(date_added, datetime.min.time())),
                content_hash=content_hash,
                raw_data=vuln,
            )
            new_items += 1
        except Exception as e:
            logger.error("Error processing KEV item %s: %s", vuln.get("cveID"), e)

    logger.info("Fetched %d new KEV items", new_items)
    return new_items


def _rss_raw(entry) -> Dict:
    """JSON-safe subset of a feedparser entry."""
    return {k: entry.get(k) for k in ("id", "title", "link", "published", "updated", "author") if entry.get(k)}


@shared_task
def fetch_rss_feeds():
    logger.info("Fetching RSS feeds...")
    total_new = 0
    for url, source in RSS_FEEDS:
        try:
            feed = feedparser.parse(url, agent=HTTP_HEADERS["User-Agent"])
            if feed.bozo and not feed.entries:
                logger.warning("Feed %s returned no entries (%s)", source, feed.get("bozo_exception"))
                continue
            for entry in feed.entries[:25]:
                title = entry.get("title", "")
                link = entry.get("link", "")
                content_hash = generate_content_hash(source, title, link)
                if ThreatItem.objects.filter(content_hash=content_hash).exists():
                    continue

                pub = entry.get("published_parsed") or entry.get("updated_parsed")
                published_at = datetime(*pub[:6], tzinfo=dt_timezone.utc) if pub else None

                summary = entry.get("summary", "")
                text = f"{title} {summary}"
                ThreatItem.objects.create(
                    source=source,
                    title=title,
                    url=link,
                    description=summary,
                    is_zero_day=has_keyword(title, "zero-day") or has_keyword(title, "0-day"),
                    is_ransomware=has_keyword(title, "ransomware"),
                    is_actively_exploited=is_actively_exploited(text),
                    threat_actor=identify_threat_actor(text),
                    risk_score=calculate_risk_score({"title": title, "source": source}),
                    published_at=published_at,
                    content_hash=content_hash,
                    raw_data=_rss_raw(entry),
                )
                total_new += 1
        except Exception as e:
            logger.error("Error fetching %s: %s", source, e)

    logger.info("Fetched %d new items from RSS feeds", total_new)
    return total_new


@shared_task
def collect_all():
    """Run both collectors (used by the 4-hourly schedule)."""
    return {"kev": fetch_kev_daily(), "rss": fetch_rss_feeds()}


# ------------------------------------------------------------------ reports
# Brief generation lives in apps.mailers.tasks (one brief per Mailer, on its own schedule).

@shared_task
def generate_daily_reports():
    """Backward-compatible entry point: dispatch any mailers that are due now."""
    from apps.mailers.tasks import dispatch_mailers

    return dispatch_mailers()


@shared_task
def cleanup_old_data():
    logger.info("Starting data cleanup...")
    for org in Organization.objects.filter(is_active=True):
        cutoff = timezone.now() - timedelta(days=org.retention_days)
        count, _ = Report.objects.filter(organization=org, created_at__lt=cutoff).delete()
        logger.info("Deleted %d old report rows for %s", count, org.name)

    cutoff_90 = timezone.now() - timedelta(days=90)
    count, _ = ThreatItem.objects.filter(discovered_at__lt=cutoff_90, processeditem__isnull=True).delete()
    logger.info("Deleted %d orphaned threat items", count)
