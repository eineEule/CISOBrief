"""
Threat condition: one 5-level answer to "how alert should we be today?".

Decided by fixed rules (not the AI) so it's consistent, explainable and works with AI off.
The AI only writes the narrative around it.

  5 SEVERE    your company is named on a leak site, or your domain is serving malware
  4 HIGH      a high-severity signal about your company (phishing lookalike, fresh infostealer hits,
              threat report naming you), an actively exploited CVE in your own technology,
              or a vendor CVE predicted >=50% likely to be exploited
  3 ELEVATED  a supplier on a leak site / hosting malware, an exploited item matching your
              industry or keywords, or 3+ new KEV entries
  2 GUARDED   high-risk items in the feeds or medium signals for you/your suppliers
  1 LOW       nothing above
"""
from typing import Dict, List, Tuple

LEVELS = {  # name, color, posture, tint
    1: ("LOW", "#16a34a", "Routine monitoring", "#f0fdf4"),
    2: ("GUARDED", "#0284c7", "Stay attentive", "#f0f9ff"),
    3: ("ELEVATED", "#ca8a04", "Heightened vigilance", "#fefce8"),
    4: ("HIGH", "#ea580c", "Act today", "#fff7ed"),
    5: ("SEVERE", "#dc2626", "Respond now", "#fef2f2"),
}


def assess(selected: List[Tuple], ew: Dict, vendors: List[str]) -> Dict:
    alerts = (ew or {}).get("alerts", [])
    vendor_set = set(vendors or [])
    level, drivers = 1, []

    def bump(n, reason):
        nonlocal level
        if n > level:
            level = n
        if reason not in [d for _, d in drivers]:
            drivers.append((n, reason))

    for a in alerts:
        own = a["relation"] == "own"
        if a["severity"] == "critical":
            bump(5, f"{a['kind_label']}: {a['target']}")
        elif a["severity"] == "high" and own:
            bump(4, f"{a['kind_label']}: {a['target']}")
        elif a["severity"] == "high" and a["relation"] == "vendor":
            bump(4, a["title"].split(" — ")[0] if a["kind"] == "likely_exploit" else a["title"])
        elif a["severity"] == "high" and a["relation"] == "supplier":
            bump(3, f"Supplier {a['target']}: {a['kind_label'].lower()}")
        elif a["severity"] == "medium" and a["relation"] in ("own", "supplier"):
            bump(2, f"{a['relation_label']} {a['target']}: {a['kind_label'].lower()}")

    kev_new = 0
    for item, matched in selected:
        exploited = item.is_actively_exploited or item.source == "kev"
        kev_new += item.source == "kev"
        stack_hits = [m for m in matched if m in vendor_set]
        if exploited and stack_hits:
            bump(4, f"Actively exploited in your stack ({', '.join(stack_hits)}): {item.cve_id or item.title[:60]}")
        elif exploited and matched:
            bump(3, f"Exploited item matching {', '.join(matched[:2])}: {item.cve_id or item.title[:60]}")
        elif item.risk_score >= 70:
            bump(2, f"High-risk item in today's feeds: {item.title[:70]}")
    if kev_new >= 3:
        bump(3, f"{kev_new} new CISA KEV entries")

    name, color, posture, tint = LEVELS[level]
    drivers.sort(key=lambda d: -d[0])
    scale = [{"n": n, "name": v[0], "color": v[1], "active": n == level} for n, v in LEVELS.items()]
    return {"level": level, "name": name, "color": color, "posture": posture, "tint": tint, "scale": scale,
            "drivers": [d for _, d in drivers[:4]], "rationale": ""}


def fallback_key_risks(selected: List[Tuple], ew: Dict, vendors: List[str]) -> List[Dict]:
    """Top 3 risks straight from the data (used when the AI is off or fails), ranked by the same rules as the level."""
    ranked = []
    sev_rank = {"critical": 5, "high": 4}
    for a in (ew or {}).get("alerts", []):
        if a["severity"] in sev_rank:
            rank = sev_rank[a["severity"]] - (1 if a["relation"] == "supplier" and a["severity"] == "high" else 0)
            ranked.append((rank, {"risk": a["title"], "why": f"{a['relation_label']} · {a['kind_label']}", "link": a["url"]}))
    vendor_set = set(vendors or [])
    for item, matched in selected:
        if (item.is_actively_exploited or item.source == "kev") and matched:
            in_stack = [m for m in matched if m in vendor_set]
            why = "Actively exploited · " + (f"in your stack ({', '.join(in_stack)})" if in_stack else f"matches {', '.join(matched[:2])}")
            ranked.append((4 if in_stack else 3, {"risk": item.title, "why": why, "link": item.url}))
    if len(ranked) < 3:
        for i, _ in selected:
            ranked.append((1, {"risk": i.title, "why": plain_why(i), "link": i.url}))
    ranked.sort(key=lambda r: -r[0])  # stable: keeps newest-first within a rank
    seen, out = set(), []
    for _, r in ranked:
        if r["risk"] not in seen:
            seen.add(r["risk"])
            out.append(r)
    return out[:3]


def plain_why(item) -> str:
    """Why an unmatched feed item matters, in words a board member can read (no bare scores)."""
    if item.source == "kev":
        return "On CISA's Known Exploited Vulnerabilities list — attackers are already using it"
    parts = []
    if item.is_actively_exploited:
        parts.append("reported as actively exploited")
    if item.is_ransomware:
        parts.append("linked to ransomware")
    if item.is_zero_day:
        parts.append("zero-day")
    src = item.get_source_display()
    lead = ", ".join(parts).capitalize() if parts else f"High-risk item from {src}"
    return f"{lead} (risk {item.risk_score}/100)"
