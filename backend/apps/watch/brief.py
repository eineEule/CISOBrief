"""Build a mailer's Early warning section from stored signals."""
from datetime import timedelta
from typing import Dict, List

from django.utils import timezone

from apps.intelligence.models import ThreatItem

from .models import KIND_LABELS, AttackGroup, WatchSignal
from .targets import is_domain, mentions_name, normalize_domain

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}
RELATION_LABEL = {"own": "Your company", "supplier": "Supplier / partner", "industry": "Your industry", "vendor": "Your technology"}
SOURCE_CREDITS = {
    "ransomlook": "RansomLook (CC BY 4.0)",
    "crtsh": "crt.sh Certificate Transparency",
    "hudsonrock": "Hudson Rock",
    "otx": "AlienVault OTX",
    "urlhaus": "abuse.ch URLhaus",
    "epss": "FIRST EPSS",
}
NEXT_STEP = {
    ("leak_site", "own"): "Activate incident response now: confirm whether data was taken, involve legal/counsel, and preserve evidence.",
    ("leak_site", "supplier"): "Contact the supplier, ask what of your data they hold was affected, and review/limit their access and integrations.",
    ("malware_hosting", "own"): "Treat as a compromise: take the URL down, find how it was uploaded, and check the host for web shells.",
    ("malware_hosting", "supplier"): "Warn the supplier and block the URL at your proxy/email gateway.",
    ("lookalike_domain", "own"): "Block the domain at email/web gateways, warn staff, and consider a takedown request.",
    ("infostealer", "own"): "Reset passwords and revoke sessions/tokens for affected staff; check their devices for malware.",
    ("infostealer", "supplier"): "Ask the supplier to rotate credentials, especially any accounts with access to your systems.",
    ("threat_report", "own"): "Review the report's indicators against your logs and block them.",
    ("threat_report", "supplier"): "Review the report and check connections from this supplier.",
    ("likely_exploit", "vendor"): "Patch or mitigate ahead of the usual cycle — exploitation is predicted before it's confirmed.",
}


def _relation(mailer, sig) -> str:
    own_domains = {normalize_domain(d) for d in mailer.watch_domains or []}
    own_names = {n.strip().lower() for n in mailer.watch_names or []}
    sup_domains = {normalize_domain(s.get("domain", "")) for s in mailer.suppliers or [] if s.get("domain")}
    sup_names = {s.get("name", "").strip().lower() for s in mailer.suppliers or [] if s.get("name")}
    t = sig.target.lower()
    if t in own_domains or t in own_names:
        return "own"
    if t in sup_domains or t in sup_names:
        return "supplier"
    if sig.target_type == "industry" and t in {i.lower() for i in mailer.industries or []}:
        return "industry"
    if sig.target_type == "vendor" and t in {v.lower() for v in mailer.vendors or []}:
        return "vendor"
    return ""


def severity(sig, relation: str) -> str:
    now = timezone.now()
    recent = sig.observed_at and sig.observed_at >= now - timedelta(days=90)
    k = sig.kind
    if k in ("leak_site", "malware_hosting"):
        return "critical" if relation == "own" else "high"
    if k == "lookalike_domain":
        d = sig.data or {}
        return "high" if (d.get("phishy") or d.get("tld_swap")) else "medium"
    if k == "infostealer":
        if relation == "own":
            return "high" if recent else "medium"
        return "medium" if recent else "info"
    if k == "threat_report":
        return {"own": "high", "supplier": "medium"}.get(relation, "info")
    if k == "likely_exploit":
        return "high" if (sig.data or {}).get("epss", 0) >= 0.5 else "medium"
    return "info"


def _targets_of(mailer):
    vals = [normalize_domain(d) for d in mailer.watch_domains or [] if is_domain(d)]
    vals += [n.strip().lower() for n in mailer.watch_names or [] if n.strip()]
    for s in mailer.suppliers or []:
        if s.get("domain"):
            vals.append(normalize_domain(s["domain"]))
        if s.get("name"):
            vals.append(s["name"].strip().lower())
    vals += [i.lower() for i in mailer.industries or []]
    vals += [v.lower() for v in mailer.vendors or []]
    return [v for v in vals if v]


def active_groups_for(industries: List[str], days: int = 30, limit: int = 5) -> List[Dict]:
    if not industries:
        return []
    groups = [g for g in AttackGroup.objects.all() if set(g.industries) & set(industries)]
    if not groups:
        return []
    since = timezone.now() - timedelta(days=days)
    corpus = " ".join(f"{t} {d}" for t, d in ThreatItem.objects.filter(discovered_at__gte=since).values_list("title", "description")[:3000])
    corpus += " " + " ".join(str((s.data or {}).get("group", "")) + " " + str((s.data or {}).get("adversary", ""))
                             for s in WatchSignal.objects.filter(discovered_at__gte=since).only("data")[:3000])
    active, known = [], []
    for g in groups:
        hit = next((n for n in g.all_names() if mentions_name(corpus, n)), None)
        row = {"name": g.name, "id": g.attack_id, "url": g.url,
               "industries": [i for i in g.industries if i in industries], "seen_as": hit}
        (active if hit else known).append(row)
    known.sort(key=lambda r: r["name"])
    return active[:limit] if active else []


def _display_names(mailer) -> Dict[str, str]:
    """Signals store targets lower-cased; show them the way the customer typed them."""
    names = list(mailer.watch_names or []) + [s.get("name", "") for s in mailer.suppliers or []]
    names += list(mailer.industries or []) + list(mailer.vendors or [])
    return {n.strip().lower(): n.strip() for n in names if n and n.strip()}


def build_early_warning(mailer, preview: bool = False) -> Dict:
    window = max(mailer.lookback, timedelta(days=30)) if preview else mailer.lookback
    since = timezone.now() - window
    targets = _targets_of(mailer)
    alerts = []
    for sig in WatchSignal.objects.filter(target__in=targets, discovered_at__gte=since).order_by("-discovered_at")[:300]:
        rel = _relation(mailer, sig)
        if not rel:
            continue
        sev = severity(sig, rel)
        alerts.append({
            "severity": sev, "relation": rel, "relation_label": RELATION_LABEL[rel],
            "kind": sig.kind, "kind_label": KIND_LABELS.get(sig.kind, sig.kind),
            "target": sig.target, "title": sig.title, "detail": sig.detail[:400], "url": sig.url,
            "when": (sig.observed_at or sig.discovered_at).date().isoformat(),
            "source": sig.source, "next_step": NEXT_STEP.get((sig.kind, rel), ""),
        })
    # Collapse repeated threat reports: one row per (who, target), newest first, with a count of the rest.
    alerts.sort(key=lambda a: a["when"], reverse=True)
    grouped, order = {}, []
    for a in alerts:
        # Only community reports repeat the same story; lookalikes, leaks, malware URLs are each separately actionable.
        key = (a["relation"], a["kind"], a["target"]) if a["kind"] == "threat_report" else id(a)
        if key not in grouped:
            a["more"], a["more_titles"] = 0, []
            grouped[key] = a
            order.append(key)
        else:
            g = grouped[key]
            if a["title"] != g["title"] and a["title"] not in g["more_titles"]:
                g["more_titles"].append(a["title"])
            g["more"] = len(g["more_titles"])
            if SEVERITY_RANK[a["severity"]] < SEVERITY_RANK[g["severity"]]:
                g["severity"] = a["severity"]
    alerts = [grouped[k] for k in order]
    display = _display_names(mailer)
    for a in alerts:
        a["target"] = display.get(a["target"], a["target"])
    alerts.sort(key=lambda a: a["when"], reverse=True)          # newest first...
    alerts.sort(key=lambda a: SEVERITY_RANK[a["severity"]])    # ...within each severity (stable sort)
    shown = [a for a in alerts if a["severity"] != "info"][:15]
    shown += [a for a in alerts if a["severity"] == "info"][: max(0, 15 - len(shown))][:5]
    actors = active_groups_for(list(mailer.industries or []))
    has_watchlist = bool(mailer.watch_domains or mailer.watch_names or mailer.suppliers)
    return {
        "alerts": shown,
        "more": max(0, len(alerts) - len(shown)),
        "critical": sum(1 for a in alerts if a["severity"] == "critical"),
        "high": sum(1 for a in alerts if a["severity"] == "high"),
        "actors": actors,
        "watching": {
            "own": [*(mailer.watch_names or []), *(mailer.watch_domains or [])],
            "suppliers": len(mailer.suppliers or []),
        },
        "has_watchlist": has_watchlist,
        "sources": sorted({SOURCE_CREDITS[a["source"]] for a in shown if a["source"] in SOURCE_CREDITS}
                          | ({"NVD"} if any(a["kind"] == "likely_exploit" for a in shown) else set())),
    }
