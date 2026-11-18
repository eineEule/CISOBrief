"""
Early-warning collectors. Each returns the number of new signals and never raises:
one source being down or rate-limited must not stop the others.

Free / open sources used:
  RansomLook (CC BY 4.0, no key)      ransomware leak-site posts naming a watched company/domain
  crt.sh (no key)                     new TLS certificates for lookalikes of your domains
  Hudson Rock free OSINT (no key)     infostealer-compromised employees per domain
  AlienVault OTX (free key)           community threat reports naming you / your industry
  abuse.ch URLhaus (free Auth-Key)    malware being served from a watched domain
  NVD + FIRST EPSS (free)             new CVEs in your vendors, ranked by predicted exploitation
  MITRE ATT&CK (free)                 groups known to target your industry
"""
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Dict, Iterable, List, Optional

import requests
from dateutil import parser as dateparser
from django.conf import settings
from django.utils import timezone

from apps.intelligence.tasks import has_keyword
from apps.mailers import catalog

from .models import AttackGroup, DomainExposure, WatchSignal
from .targets import Targets, domain_label, mentions_domain, mentions_name, registered_domain

logger = logging.getLogger(__name__)
UA = {"User-Agent": "CISO-Brief/1.0 (early-warning; contact via SITE_URL)"}

RANSOMLOOK_POSTS = "https://www.ransomlook.io/api/posts"
CRTSH = "https://crt.sh/"
HUDSONROCK_DOMAIN = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
OTX_SEARCH = "https://otx.alienvault.com/api/v1/search/pulses"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS = "https://api.first.org/data/v1/epss"
ATTACK_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

PHISHY_WORDS = ["login", "signin", "sign-in", "secure", "sso", "mail", "webmail", "portal", "support", "helpdesk",
                "verify", "account", "auth", "okta", "microsoft", "office", "o365", "m365", "vpn", "hr", "payroll", "invoice", "pay"]


def fp(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p or "").lower().encode())
        h.update(b"\x00")
    return h.hexdigest()


def parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = dateparser.parse(str(value))
        return dt if dt.tzinfo else dt.replace(tzinfo=dt_timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def save_signal(**kw) -> bool:
    _, created = WatchSignal.objects.get_or_create(fingerprint=kw.pop("fingerprint"), defaults=kw)
    return created


def _get(url, **kw):
    kw.setdefault("timeout", 60)
    headers = {**UA, **kw.pop("headers", {})}
    r = requests.get(url, headers=headers, **kw)
    r.raise_for_status()
    return r


# ------------------------------------------------------------------ RansomLook

def collect_ransomlook(targets: Targets, days: int = 3) -> int:
    if not (targets.all_domains or targets.names):
        return 0
    try:
        data = _get(RANSOMLOOK_POSTS, params={"days": days}).json()
    except Exception as e:
        logger.error("RansomLook fetch failed: %s", e)
        return 0
    posts = data if isinstance(data, list) else data.get("posts") or data.get("data") or []
    new = 0
    for post in posts:
        if not isinstance(post, dict):
            continue
        title = str(post.get("post_title") or post.get("title") or "")
        group = str(post.get("group_name") or post.get("group") or "unknown")
        text = " ".join(str(post.get(k) or "") for k in ("post_title", "title", "description", "website", "link"))
        for target, ttype in targets.matches(text):
            new += save_signal(
                fingerprint=fp("ransomlook", group, title, target),
                kind="leak_site", source="ransomlook", target=target, target_type=ttype,
                title=f"{title} — claimed by {group}"[:500],
                detail=str(post.get("description") or "")[:1500],
                url=f"https://www.ransomlook.io/group/{requests.utils.quote(group)}",
                observed_at=parse_dt(post.get("discovered")),
                data={"group": group, "post_title": title},
            )
    logger.info("RansomLook: %d posts scanned, %d new signals", len(posts), new)
    return new


# ---------------------------------------------------------------------- crt.sh

def collect_crtsh(targets: Targets, days: int = 14) -> int:
    new = 0
    cutoff = timezone.now() - timedelta(days=days)
    for domain in sorted(targets.own_domains):
        label = domain_label(domain)
        if len(label) < 5:
            logger.info("crt.sh: skipping %s (label %r too short to search without noise)", domain, label)
            continue
        own = {registered_domain(d) for d in targets.org_domains.get(domain, {domain})}
        try:
            rows = _get(CRTSH, params={"q": f"%{label}%", "output": "json", "exclude": "expired", "deduplicate": "Y"},
                        timeout=120).json()
        except Exception as e:
            logger.error("crt.sh query for %s failed: %s", domain, e)
            continue
        seen = set()
        for row in rows if isinstance(rows, list) else []:
            issued = parse_dt(row.get("not_before") or row.get("entry_timestamp"))
            if not issued or issued < cutoff:
                continue
            raw = str(row.get("name_value", "")).splitlines() + [str(row.get("common_name") or "")]
            names = {n.strip().lower().lstrip("*.").removeprefix("www.") for n in raw}
            for host in names:
                if not host or label not in host:
                    continue
                reg = registered_domain(host)
                if not reg or reg in own or reg in seen:
                    continue
                seen.add(reg)
                phishy = [w for w in PHISHY_WORDS if w in host.replace(label, " ")]
                tld_swap = domain_label(reg) == label  # e.g. acme.com -> acme.co / acme.com.co
                new += save_signal(
                    fingerprint=fp("crtsh", domain, reg),
                    kind="lookalike_domain", source="crtsh", target=domain, target_type="domain",
                    title=f"Certificate issued for lookalike {host}",
                    detail=f"Issuer: {row.get('issuer_name', '')}. "
                           + ("Same name on a different domain ending (typosquat). " if tld_swap else "")
                           + (f"Contains phishing-style words: {', '.join(phishy)}." if phishy else ""),
                    url=f"https://crt.sh/?id={row.get('id')}",
                    observed_at=issued,
                    data={"host": host, "registered_domain": reg, "phishy": phishy, "tld_swap": tld_swap},
                )
    logger.info("crt.sh: %d new lookalike signals", new)
    return new


# ----------------------------------------------------------------- Hudson Rock

def _hr_field(data: Dict, *names):
    for container in (data, data.get("data") if isinstance(data.get("data"), dict) else {}):
        for n in names:
            if container and container.get(n) is not None:
                return container.get(n)
    return None


def collect_hudsonrock(targets: Targets) -> int:
    new = 0
    for domain in sorted(targets.all_domains):
        try:
            data = _get(HUDSONROCK_DOMAIN, params={"domain": domain}, timeout=60).json()
            time.sleep(0.3)  # free tier: 50 requests / 10 seconds
        except Exception as e:
            logger.error("Hudson Rock lookup for %s failed: %s", domain, e)
            continue
        if not isinstance(data, dict):
            continue
        employees = int(_hr_field(data, "employees", "compromised_employees") or 0)
        users = int(_hr_field(data, "users", "compromised_users") or 0)
        third = int(_hr_field(data, "third_parties") or 0)
        last_emp = parse_dt(_hr_field(data, "last_employee_compromised"))
        prev = DomainExposure.objects.filter(domain=domain).first()
        changed = prev is None or employees > prev.employees or (last_emp and (not prev.last_employee_compromised or last_emp > prev.last_employee_compromised))
        DomainExposure.objects.update_or_create(domain=domain, defaults={
            "employees": employees, "users": users, "third_parties": third, "last_employee_compromised": last_emp})
        if employees and changed:
            delta = employees - (prev.employees if prev else 0)
            title = (f"{delta:,} newly reported infostealer-compromised employee(s) at {domain}" if prev
                     else f"{employees:,} employee(s) at {domain} have had credentials stolen by infostealer malware")
            new += save_signal(
                fingerprint=fp("hudsonrock", domain, employees, last_emp),
                kind="infostealer", source="hudsonrock", target=domain, target_type="domain",
                title=title,
                detail=(f"Most recent employee infection: {last_emp:%b %d, %Y}. " if last_emp else "")
                       + f"Also {users:,} customer/user accounts and {third:,} third-party accounts. "
                       + "Infostealer logs are a common starting point for ransomware intrusions.",
                url="https://www.hudsonrock.com/free-tools",
                observed_at=last_emp,
                data={"employees": employees, "users": users, "third_parties": third, "delta": delta},
            )
    logger.info("Hudson Rock: %d new signals", new)
    return new


# ------------------------------------------------------------------------ OTX

def _otx_search(q: str, limit=10):
    r = _get(OTX_SEARCH, params={"q": q, "sort": "-modified", "limit": limit},
             headers={"X-OTX-API-KEY": settings.OTX_API_KEY}, timeout=60)
    return r.json().get("results", [])


def collect_otx(targets: Targets, days: int = 30) -> int:
    if not settings.OTX_API_KEY:
        logger.info("OTX: OTX_API_KEY not set, skipping")
        return 0
    new = 0
    cutoff = timezone.now() - timedelta(days=days)
    queries = [(d, "domain") for d in sorted(targets.all_domains)] + [(n, "name") for n in sorted(targets.names)]
    for q, ttype in queries:
        try:
            pulses = _otx_search(f'"{q}"')
        except Exception as e:
            logger.error("OTX search %r failed: %s", q, e)
            continue
        for p in pulses:
            modified = parse_dt(p.get("modified") or p.get("created"))
            if not modified or modified < cutoff:
                continue
            text = " ".join([str(p.get("name", "")), str(p.get("description", "")), " ".join(map(str, p.get("tags") or [])),
                             " ".join(map(str, p.get("references") or []))])
            if not (mentions_domain(text, q) if ttype == "domain" else mentions_name(text, q)):
                continue
            new += save_signal(
                fingerprint=fp("otx", p.get("id"), q),
                kind="threat_report", source="otx", target=q.lower(), target_type=ttype,
                title=str(p.get("name", "OTX pulse"))[:500],
                detail=str(p.get("description", ""))[:1500],
                url=f"https://otx.alienvault.com/pulse/{p.get('id')}",
                observed_at=modified,
                data={"adversary": p.get("adversary"), "industries": p.get("industries"), "tags": (p.get("tags") or [])[:10]},
            )
    # Industry: recent pulses OTX authors tagged with the industry itself
    ind_cutoff = timezone.now() - timedelta(days=7)
    for industry in sorted(targets.industries):
        terms = [industry.lower()] + [t.lower() for t in catalog.INDUSTRIES.get(industry, [])]
        try:
            pulses = _otx_search(industry.split("/")[0].split("&")[0].strip(), limit=20)
        except Exception as e:
            logger.error("OTX industry search %r failed: %s", industry, e)
            continue
        kept = 0
        for p in pulses:
            modified = parse_dt(p.get("modified") or p.get("created"))
            tagged = [str(i).lower() for i in (p.get("industries") or [])]
            if not modified or modified < ind_cutoff or not any(any(t in i for t in terms) for i in tagged):
                continue
            new += save_signal(
                fingerprint=fp("otx-industry", p.get("id"), industry),
                kind="threat_report", source="otx", target=industry.lower(), target_type="industry",
                title=str(p.get("name", "OTX pulse"))[:500], detail=str(p.get("description", ""))[:1500],
                url=f"https://otx.alienvault.com/pulse/{p.get('id')}", observed_at=modified,
                data={"adversary": p.get("adversary"), "industries": p.get("industries")},
            )
            kept += 1
            if kept >= 5:
                break
    logger.info("OTX: %d new signals", new)
    return new


# -------------------------------------------------------------------- URLhaus

def collect_urlhaus(targets: Targets, days: int = 30) -> int:
    if not settings.ABUSECH_AUTH_KEY:
        logger.info("URLhaus: ABUSECH_AUTH_KEY not set, skipping")
        return 0
    new = 0
    cutoff = timezone.now() - timedelta(days=days)
    for domain in sorted(targets.all_domains):
        try:
            r = requests.post(URLHAUS_HOST, data={"host": domain}, headers={**UA, "Auth-Key": settings.ABUSECH_AUTH_KEY}, timeout=60)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.error("URLhaus lookup for %s failed: %s", domain, e)
            continue
        if data.get("query_status") != "ok":
            continue
        kept = 0
        for u in data.get("urls") or []:
            added = parse_dt(u.get("date_added"))
            if u.get("url_status") != "online" and (not added or added < cutoff):
                continue
            new += save_signal(
                fingerprint=fp("urlhaus", u.get("id") or u.get("url"), domain),
                kind="malware_hosting", source="urlhaus", target=domain, target_type="domain",
                title=f"Malware URL on {domain} ({u.get('url_status', 'unknown')}): {u.get('threat') or 'malware'}",
                detail=f"{u.get('url', '')} — tags: {', '.join(u.get('tags') or []) or 'none'}",
                url=u.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
                observed_at=added, data={"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat")},
            )
            kept += 1
            if kept >= 5:
                break
    logger.info("URLhaus: %d new signals", new)
    return new


# ----------------------------------------------------------- NVD + FIRST EPSS

def epss_scores(cves: Iterable[str]) -> Dict[str, Dict]:
    cves = sorted({c for c in cves if c and c.upper().startswith("CVE-")})
    out = {}
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            data = _get(EPSS, params={"cve": ",".join(batch)}, timeout=60).json()
        except Exception as e:
            logger.error("EPSS batch failed: %s", e)
            continue
        for row in data.get("data", []):
            try:
                out[row["cve"].upper()] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
            except (KeyError, ValueError, TypeError):
                pass
    return out


def enrich_threat_items_epss(days: int = 14) -> int:
    from apps.intelligence.models import ThreatItem

    items = list(ThreatItem.objects.filter(discovered_at__gte=timezone.now() - timedelta(days=days)).exclude(cve_id="").filter(epss__isnull=True))
    scores = epss_scores(i.cve_id for i in items)
    n = 0
    for item in items:
        s = scores.get(item.cve_id.upper())
        if s:
            item.epss, item.epss_percentile = s["epss"], s["percentile"]
            item.save(update_fields=["epss", "epss_percentile"])
            n += 1
    return n


def collect_likely_exploits(targets: Targets, days: int = 30, min_epss: float = 0.10, min_percentile: float = 0.95) -> int:
    """New CVEs for watched vendors (NVD keyword search) that EPSS predicts will be exploited, and aren't in KEV yet."""
    from apps.intelligence.models import ThreatItem

    if not targets.vendors:
        return 0
    end = timezone.now()
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    pause = 0.7 if settings.NVD_API_KEY else 6.5
    found: Dict[str, Dict] = {}
    for vendor in sorted(targets.vendors):
        keyword = (catalog.VENDORS.get(vendor) or [vendor])[0]
        try:
            data = _get(NVD_CVES, params={"keywordSearch": keyword, "pubStartDate": start.strftime(fmt),
                                           "pubEndDate": end.strftime(fmt), "resultsPerPage": 200},
                        headers=headers, timeout=90).json()
        except Exception as e:
            logger.error("NVD search for %s failed: %s", vendor, e)
            continue
        finally:
            time.sleep(pause)
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id", "").upper()
            desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            if cid and has_keyword(desc, keyword):
                found.setdefault(cid, {"vendor": vendor, "description": desc, "published": cve.get("published")})
    if not found:
        return 0
    kev = set(ThreatItem.objects.filter(source="kev").values_list("cve_id", flat=True))
    scores = epss_scores(found)
    new = 0
    for cid, info in found.items():
        s = scores.get(cid)
        if not s or cid in kev or (s["epss"] < min_epss and s["percentile"] < min_percentile):
            continue
        new += save_signal(
            fingerprint=fp("epss", cid),
            kind="likely_exploit", source="epss", target=info["vendor"].lower(), target_type="vendor",
            title=f"{cid} ({info['vendor']}) — {s['epss']:.0%} predicted chance of exploitation in the next 30 days",
            detail=info["description"][:1200],
            url=f"https://nvd.nist.gov/vuln/detail/{cid}",
            observed_at=parse_dt(info.get("published")),
            data={"cve": cid, **s, "vendor": info["vendor"]},
        )
    logger.info("NVD+EPSS: %d candidate CVEs, %d new likely-exploit signals", len(found), new)
    return new


# --------------------------------------------------------------- MITRE ATT&CK

def refresh_attack_groups() -> int:
    try:
        bundle = _get(ATTACK_STIX, timeout=180).json()
    except Exception as e:
        logger.error("ATT&CK download failed: %s", e)
        return 0
    n = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not ref.get("external_id"):
            continue
        desc = obj.get("description", "")
        industries = [ind for ind, terms in catalog.INDUSTRIES.items() if any(has_keyword(desc, t) for t in [ind] + terms)]
        AttackGroup.objects.update_or_create(attack_id=ref["external_id"], defaults={
            "name": obj.get("name", ""), "aliases": obj.get("aliases") or [], "description": desc[:5000],
            "url": ref.get("url", ""), "industries": industries, "modified": parse_dt(obj.get("modified")),
        })
        n += 1
    logger.info("ATT&CK: %d groups refreshed", n)
    return n
