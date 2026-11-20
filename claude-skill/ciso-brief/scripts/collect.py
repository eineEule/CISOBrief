#!/usr/bin/env python3
"""
CISO Brief collector: fetch free threat-intel sources, match them to your profile, score them,
and set the threat condition. Standard library only (Python 3.9+); no installs.

    python collect.py --config ../config.ini --out brief.json [--state state.json]

Output (brief.json) is the raw material for the brief: matched items, early-warning alerts,
the threat condition (rules-based, never decided by AI), fallback key risks, and a status line
for every source (ok / skipped / failed, with the reason) so nothing is silently missing.

Every source is optional and isolated: one being down, blocked or keyless never stops the others.
"""
import argparse
import configparser
import email.utils
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone

UA = "CISO-Brief/1.0 (+https://github.com/eineEule/CISOBrief)"

URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisa_news": "https://www.cisa.gov/news.xml",
    "hacker_news": "https://feeds.feedburner.com/TheHackersNews",
    "ransomlook": "https://www.ransomlook.io/api/posts",
    "crtsh": "https://crt.sh/",
    "hudsonrock": "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
    "otx": "https://otx.alienvault.com/api/v1/search/pulses",
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/host/",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "epss": "https://api.first.org/data/v1/epss",
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
}

SOURCE_NAMES = {
    "kev": "CISA Known Exploited Vulnerabilities",
    "cisa_news": "CISA News",
    "hacker_news": "The Hacker News",
    "ransomlook": "RansomLook (CC BY 4.0)",
    "crtsh": "crt.sh Certificate Transparency",
    "hudsonrock": "Hudson Rock",
    "nvd_epss": "NVD + FIRST EPSS",
    "mitre_attack": "MITRE ATT&CK®",
    "otx": "AlienVault OTX",
    "urlhaus": "abuse.ch URLhaus",
}

VENDORS = {
    "Microsoft": ["microsoft", "windows", "exchange", "azure", "entra", "outlook", "sharepoint", "defender", "office 365", "microsoft 365"],
    "Cisco": ["cisco", "meraki", "anyconnect", "ios xe", "webex"],
    "Fortinet": ["fortinet", "fortios", "fortigate", "fortiweb", "fortimanager", "forticlient", "fortisiem"],
    "Palo Alto Networks": ["palo alto", "pan-os", "globalprotect", "cortex xdr"],
    "Ivanti": ["ivanti", "connect secure", "epmm", "pulse secure"],
    "Citrix / NetScaler": ["citrix", "netscaler"],
    "VMware / Broadcom": ["vmware", "esxi", "vcenter", "workspace one"],
    "Okta": ["okta"],
    "Google": ["google", "chrome", "chromium", "android"],
    "Apple": ["apple", "macos", "iphone", "ipados", "safari", "webkit"],
    "AWS": ["aws", "amazon web services"],
    "Oracle": ["oracle", "weblogic", "e-business suite"],
    "SAP": ["sap", "netweaver"],
    "Atlassian": ["atlassian", "confluence", "jira", "bitbucket"],
    "SonicWall": ["sonicwall"],
    "Juniper": ["juniper", "junos"],
    "Veeam": ["veeam"],
    "ConnectWise": ["connectwise", "screenconnect"],
    "Linux / Open source": ["linux", "openssh", "apache", "nginx", "openssl"],
    "Procore": ["procore"],
    "Autodesk": ["autodesk", "autocad", "revit", "bim 360"],
    "Trimble": ["trimble", "viewpoint vista", "tekla"],
    "Bentley Systems": ["bentley systems", "microstation", "projectwise"],
    "Siemens (ICS)": ["siemens", "simatic"],
    "Rockwell (ICS)": ["rockwell", "allen-bradley", "factorytalk"],
    "Schneider Electric (ICS)": ["schneider electric", "modicon"],
}

INDUSTRIES = {
    "Construction": ["construction"],
    "Manufacturing / Industrial": ["manufacturing", "industrial", "ics", "scada", "operational technology"],
    "Energy & Utilities": ["energy", "utility", "utilities", "power grid", "electric", "oil and gas"],
    "Water & Wastewater": ["water utility", "wastewater", "water treatment"],
    "Healthcare": ["healthcare", "hospital", "medical", "patient"],
    "Financial Services": ["financial", "bank", "banking", "fintech", "payment"],
    "Government": ["government", "federal", "municipal", "state agency"],
    "Education": ["education", "university", "school", "k-12"],
    "Retail": ["retail", "e-commerce", "point-of-sale"],
    "Transportation & Logistics": ["transportation", "logistics", "shipping", "aviation", "rail"],
    "Technology / SaaS": ["saas", "software supply chain", "cloud provider"],
    "Defense": ["defense", "defence", "military"],
}

EXPLOITED_PHRASES = ["actively exploited", "exploited in the wild", "under active exploitation",
                     "active exploitation", "exploited in attacks", "being exploited"]
PHISHY_WORDS = ["login", "signin", "sign-in", "secure", "sso", "mail", "webmail", "portal", "support", "helpdesk",
                "verify", "account", "auth", "okta", "microsoft", "office", "o365", "m365", "vpn", "hr", "payroll", "invoice", "pay"]
MULTI_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "gov.au",
                        "co.nz", "org.nz", "co.jp", "or.jp", "com.br", "com.mx", "co.in", "co.za", "com.cn", "com.sg",
                        "com.tr", "com.hk", "co.kr", "com.ar", "co.il", "com.my", "com.ph", "com.tw", "com.vn"}

KIND_LABELS = {
    "leak_site": "Named on a ransomware leak site",
    "malware_hosting": "Domain is hosting malware",
    "lookalike_domain": "Lookalike domain certificate issued",
    "infostealer": "Employee credentials stolen by infostealer malware",
    "threat_report": "Mentioned in a community threat report",
    "likely_exploit": "New CVE in your stack likely to be exploited soon",
}
RELATION_LABEL = {"own": "Your company", "supplier": "Supplier / partner", "industry": "Your industry", "vendor": "Your technology"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}
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
    ("likely_exploit", "vendor"): "Patch or mitigate ahead of the usual cycle: exploitation is predicted before it's confirmed.",
}
LEVELS = {  # name, color, posture, tint
    1: ("LOW", "#16a34a", "Routine monitoring", "#f0fdf4"),
    2: ("GUARDED", "#0284c7", "Stay attentive", "#f0f9ff"),
    3: ("ELEVATED", "#ca8a04", "Heightened vigilance", "#fefce8"),
    4: ("HIGH", "#ea580c", "Act today", "#fff7ed"),
    5: ("SEVERE", "#dc2626", "Respond now", "#fef2f2"),
}
KEY_ENV = {"otx_api_key": "CISO_BRIEF_OTX_API_KEY", "abusech_auth_key": "CISO_BRIEF_ABUSECH_AUTH_KEY",
           "nvd_api_key": "CISO_BRIEF_NVD_API_KEY"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
NOW = datetime.now(timezone.utc)


# ----------------------------------------------------------------------------- helpers

def log(msg):
    print(msg, file=sys.stderr)


class Blocked(Exception):
    """The network refused the request before it reached the site (sandbox / proxy)."""


def http(url, params=None, headers=None, data=None, timeout=60, as_json=True):
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, "Accept-Encoding": "gzip", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
    except urllib.error.HTTPError as e:
        if e.code in (403, 407) and "proxy" in str(e.headers.get("Server", "") + str(e.reason)).lower():
            raise Blocked(f"blocked by network proxy ({e.code})")
        raise
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if any(s in reason.lower() for s in ("name or service not known", "nodename nor servname", "temporary failure in name resolution",
                                              "network is unreachable", "getaddrinfo failed", "tunnel connection failed")):
            raise Blocked(f"no network route ({reason})")
        raise
    text = raw.decode("utf-8", errors="replace")
    return json.loads(text) if as_json else text


def parse_dt(value):
    if not value:
        return None
    s = str(value).strip()
    try:
        s2 = s.replace("Z", "+00:00")
        s2 = re.sub(r"(\.\d{6})\d+", r"\1", s2)  # trim >6 fractional digits
        dt = datetime.fromisoformat(s2)
    except ValueError:
        try:
            dt = email.utils.parsedate_to_datetime(s)
        except (TypeError, ValueError, IndexError):
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat() if dt else None


def _rx(term):
    return re.compile(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])")


_RX_CACHE = {}


def has_term(text, term):
    if not term:
        return False
    rx = _RX_CACHE.get(term)
    if rx is None:
        rx = _RX_CACHE[term] = _rx(term)
    return bool(rx.search((text or "").lower()))


def mentions_name(text, name):
    return len(name) >= 4 and has_term(text, name)


def mentions_domain(text, domain):
    return bool(domain) and bool(re.search(r"(?<![a-z0-9.-])(?:www\.)?" + re.escape(domain.lower()) + r"(?![a-z0-9-])", (text or "").lower()))


def normalize_domain(v):
    v = (v or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    return v[4:] if v.startswith("www.") else v


def registered_domain(host):
    parts = normalize_domain(host).lstrip("*.").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_label(domain):
    return registered_domain(domain).split(".")[0]


def split_list(value):
    return [x.strip() for x in re.split(r"[,\n]", value or "") if x.strip()]


def truthy(value, default=True):
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in ("1", "yes", "true", "on", "y")


def fingerprint(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p or "").lower().encode())
        h.update(b"\0")
    return h.hexdigest()[:16]


# ----------------------------------------------------------------------------- config

class Profile:
    def __init__(self, cfg):
        p = cfg["profile"] if cfg.has_section("profile") else {}
        self.company = (p.get("company") or "").strip()
        self.names = [n for n in [self.company] + split_list(p.get("other_names")) if len(n) >= 4]
        self.domains = [normalize_domain(d) for d in split_list(p.get("domains")) if "." in d]
        self.industries, self.industry_terms, extra = [], [], []
        by_name = {k.lower(): k for k in INDUSTRIES}
        by_term = {t: k for k, ts in INDUSTRIES.items() for t in ts}
        for v in split_list(p.get("industries")):
            hit = by_name.get(v.lower()) or by_term.get(v.lower())
            if hit and hit not in self.industries:
                self.industries.append(hit)
            elif not hit:
                extra.append(v)
        for i in self.industries:
            self.industry_terms += [(i, t) for t in INDUSTRIES[i]]
        self.audience = (p.get("audience") or "executive").strip().lower()
        if self.audience not in ("executive", "technical"):
            self.audience = "executive"
        self.brief_name = (p.get("brief_name") or "Threat Brief").strip()
        # technology: "Name" (built-in) or "Name = term1, term2"
        self.vendors, self.vendor_terms = [], []
        if cfg.has_section("technology"):
            for name, val in cfg.items("technology"):
                name = name.strip()
                terms = split_list(val) if val else VENDORS.get(name, [name.lower()])
                self.vendors.append(name)
                self.vendor_terms += [(name, t.lower()) for t in terms]
        self.suppliers = []
        if cfg.has_section("suppliers"):
            for name, val in cfg.items("suppliers"):
                d = normalize_domain(val or "")
                self.suppliers.append({"name": name.strip(), "domain": d if "." in d else ""})
        self.keywords = [k.strip() for k, _ in cfg.items("keywords")] if cfg.has_section("keywords") else []
        self.keywords += extra
        self.supplier_domains = {s["domain"] for s in self.suppliers if s["domain"]} - set(self.domains)
        self.supplier_names = [s["name"] for s in self.suppliers if len(s["name"]) >= 4]

    @property
    def all_domains(self):
        return sorted(set(self.domains) | self.supplier_domains)

    def match_terms(self):
        terms = list(self.vendor_terms) + list(self.industry_terms) + [(k, k.lower()) for k in self.keywords]
        terms += [(n, n.lower()) for n in self.names + self.supplier_names]
        return terms

    def relation_of(self, target):
        t = (target or "").lower()
        if t in self.domains or t in {n.lower() for n in self.names}:
            return "own"
        if t in self.supplier_domains or t in {n.lower() for n in self.supplier_names}:
            return "supplier"
        return ""

    def supplier_key(self, target):
        t = (target or "").lower()
        for s in self.suppliers:
            if t in (s["name"].lower(), s["domain"]):
                return s["name"].lower()
        return t

    def display(self, target):
        t = (target or "").lower()
        for n in self.names + self.supplier_names + self.vendors + self.industries:
            if n.lower() == t:
                return n
        for s in self.suppliers:
            if s["domain"] and s["domain"] == t:
                return s["name"]
        return target

    def as_dict(self):
        return {"company": self.company, "names": self.names, "domains": self.domains, "industries": self.industries,
                "audience": self.audience, "brief_name": self.brief_name, "technology": self.vendors,
                "suppliers": self.suppliers, "keywords": self.keywords}


def load_config(path):
    cfg = configparser.ConfigParser(allow_no_value=True, interpolation=None, inline_comment_prefixes=("#", ";"))
    cfg.optionxform = str  # keep "Microsoft", "Palo Alto Networks" as typed
    with open(path, encoding="utf-8") as f:
        cfg.read_file(f)
    return cfg


def get_key(cfg, name):
    env = os.environ.get(KEY_ENV[name], "").strip()
    if env:
        return env
    return (cfg.get("keys", name, fallback="") or "").strip()


# ----------------------------------------------------------------------------- scoring

def risk_score(source, title):
    if source == "kev":
        return 95
    score = 40
    if has_term(title, "ransomware"):
        score += 30
    if has_term(title, "zero-day") or has_term(title, "0-day"):
        score += 25
    if any(has_term(title, p) for p in EXPLOITED_PHRASES):
        score += 25
    if has_term(title, "critical"):
        score += 20
    if has_term(title, "remote code execution") or has_term(title, "rce"):
        score += 15
    return min(score, 95)


def severity(kind, relation, data, observed):
    recent = observed is not None and observed >= NOW - timedelta(days=90)
    if kind in ("leak_site", "malware_hosting"):
        return "critical" if relation == "own" else "high"
    if kind == "lookalike_domain":
        return "high" if (data.get("phishy") or data.get("tld_swap")) else "medium"
    if kind == "infostealer":
        if relation == "own":
            return "high" if recent else "medium"
        return "medium" if recent else "info"
    if kind == "threat_report":
        return {"own": "high", "supplier": "medium"}.get(relation, "info")
    if kind == "likely_exploit":
        return "high" if data.get("epss", 0) >= 0.5 else "medium"
    return "info"


# ----------------------------------------------------------------------------- collectors

class Run:
    def __init__(self, cfg, profile, state):
        self.cfg, self.p, self.state = cfg, profile, state
        self.items, self.signals, self.sources = [], [], []
        self.lookback_days = max(1, cfg.getint("brief", "lookback_days", fallback=1))
        self.since = NOW - timedelta(days=self.lookback_days)
        self.kev_cves = set()

    def enabled(self, key):
        return truthy(self.cfg.get("sources", key, fallback="on"))

    def status(self, key, status, detail="", count=0):
        self.sources.append({"key": key, "name": SOURCE_NAMES[key], "status": status, "detail": detail, "count": count})
        log(f"[{status:7}] {SOURCE_NAMES[key]}: {detail or count}")

    def guard(self, key, fn, need=None, missing=""):
        if not self.enabled(key):
            return self.status(key, "skipped", "turned off in config")
        if need is not None and not need:
            return self.status(key, "skipped", missing)
        try:
            n = fn()
            self.status(key, "ok", count=n)
        except Blocked as e:
            self.status(key, "failed", f"network blocked here: {e}")
        except Exception as e:  # noqa: BLE001: one source never breaks the run
            self.status(key, "failed", f"{type(e).__name__}: {str(e)[:160]}")

    def add_signal(self, kind, source, target, relation, title, url, observed=None, detail="", data=None):
        data = data or {}
        self.signals.append({
            "id": fingerprint(source, kind, target, title), "kind": kind, "kind_label": KIND_LABELS[kind],
            "source": source, "target": self.p.display(target), "relation": relation,
            "relation_label": RELATION_LABEL[relation], "title": title[:500], "detail": (detail or "")[:400],
            "url": url, "when": (observed or NOW).date().isoformat(), "observed": iso(observed),
            "severity": severity(kind, relation, data, observed),
            "next_step": NEXT_STEP.get((kind, relation), ""), "data": data,
        })

    def watched_matches(self, text):
        hits = [(n, "name") for n in self.p.names + self.p.supplier_names if mentions_name(text, n)]
        hits += [(d, "domain") for d in self.p.all_domains if mentions_domain(text, d)]
        return hits

    def entities(self, text):
        """One (target, relation) per company or supplier mentioned, even if both its name and domain appear."""
        out, seen = [], set()
        for target, _ in self.watched_matches(text):
            rel = self.p.relation_of(target)
            if not rel:
                continue
            key = rel if rel == "own" else self.p.supplier_key(target)
            if key in seen:
                continue
            seen.add(key)
            out.append((target, rel))
        return out

    # -- feeds -----------------------------------------------------------------
    def kev(self):
        data = http(URLS["kev"], timeout=60)
        cutoff = (NOW - timedelta(days=max(2, self.lookback_days + 1))).date()
        n = 0
        for v in data.get("vulnerabilities", []):
            self.kev_cves.add(v.get("cveID", "").upper())
            try:
                added = date.fromisoformat(v["dateAdded"])
            except (KeyError, ValueError):
                continue
            if added < cutoff:
                continue
            cve = v.get("cveID", "")
            self.items.append({
                "source": "kev", "source_name": SOURCE_NAMES["kev"], "title": f"{cve} — {v.get('vulnerabilityName', '')}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}", "description": v.get("shortDescription", ""),
                "cve": cve, "published": added.isoformat(), "exploited": True,
                "ransomware": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
                "risk": 95, "vendor_project": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                "required_action": v.get("requiredAction", ""), "due": v.get("dueDate", ""),
            })
            n += 1
        return n

    def rss(self, key):
        text = http(URLS[key], as_json=False, timeout=45)
        root = ET.fromstring(text)
        ns = {"a": "http://www.w3.org/2005/Atom"}
        entries = []
        for it in root.iter("item"):
            entries.append((it.findtext("title"), it.findtext("link"), it.findtext("description"), it.findtext("pubDate")))
        for it in root.findall(".//a:entry", ns):
            link = it.find("a:link", ns)
            entries.append((it.findtext("a:title", namespaces=ns), link.get("href") if link is not None else "",
                            it.findtext("a:summary", namespaces=ns) or it.findtext("a:content", namespaces=ns),
                            it.findtext("a:updated", namespaces=ns) or it.findtext("a:published", namespaces=ns)))
        n = 0
        for title, link, desc, published in entries:
            pub = parse_dt(published)
            if not title or (pub and pub < self.since):
                continue
            desc = re.sub(r"<[^>]+>", " ", desc or "")
            desc = re.sub(r"\s+", " ", desc).strip()[:1500]
            text_all = f"{title} {desc}"
            cves = sorted({c.upper() for c in CVE_RE.findall(text_all)})
            self.items.append({
                "source": key, "source_name": SOURCE_NAMES[key], "title": title.strip(), "url": (link or "").strip(),
                "description": desc, "cve": cves[0] if cves else "", "cves": cves, "published": iso(pub),
                "exploited": any(has_term(text_all, p) for p in EXPLOITED_PHRASES),
                "ransomware": has_term(text_all, "ransomware"), "risk": risk_score(key, title),
            })
            n += 1
        return n

    # -- early warning ---------------------------------------------------------
    def ransomlook(self):
        days = max(3, self.lookback_days)
        data = http(URLS["ransomlook"], params={"days": days}, timeout=90)
        posts = data if isinstance(data, list) else (data.get("posts") or data.get("data") or [])
        n = 0
        for post in posts:
            if not isinstance(post, dict):
                continue
            title = str(post.get("post_title") or post.get("title") or "")
            group = str(post.get("group_name") or post.get("group") or "unknown")
            text = " ".join(str(post.get(k) or "") for k in ("post_title", "title", "description", "website", "link"))
            for target, rel in self.entities(text):
                self.add_signal("leak_site", "ransomlook", target, rel, f"{title} — claimed by {group}",
                                f"https://www.ransomlook.io/group/{urllib.parse.quote(group)}",
                                parse_dt(post.get("discovered")), str(post.get("description") or ""), {"group": group})
                n += 1
        return n

    def crtsh(self):
        n, cutoff = 0, NOW - timedelta(days=14)
        own = {registered_domain(d) for d in self.p.domains}
        for domain in self.p.domains:
            label = domain_label(domain)
            if len(label) < 5:
                log(f"crt.sh: skipping {domain} (name '{label}' too short to search without noise)")
                continue
            rows = http(URLS["crtsh"], params={"q": f"%{label}%", "output": "json", "exclude": "expired", "deduplicate": "Y"},
                        timeout=120)
            seen = set()
            for row in rows if isinstance(rows, list) else []:
                issued = parse_dt(row.get("not_before") or row.get("entry_timestamp"))
                if not issued or issued < cutoff:
                    continue
                names = {h.strip().lower().lstrip("*.").removeprefix("www.")
                         for h in str(row.get("name_value", "")).splitlines() + [str(row.get("common_name") or "")]}
                for host in names:
                    if not host or label not in host:
                        continue
                    reg = registered_domain(host)
                    if not reg or reg in own or reg in seen:
                        continue
                    seen.add(reg)
                    phishy = [w for w in PHISHY_WORDS if w in host.replace(label, " ")]
                    tld_swap = domain_label(reg) == label
                    self.add_signal("lookalike_domain", "crtsh", domain, "own", f"Certificate issued for lookalike {host}",
                                    f"https://crt.sh/?id={row.get('id')}", issued,
                                    f"Issuer: {row.get('issuer_name', '')}."
                                    + (" Same name on a different domain ending (typosquat)." if tld_swap else "")
                                    + (f" Contains phishing-style words: {', '.join(phishy)}." if phishy else ""),
                                    {"host": host, "phishy": phishy, "tld_swap": tld_swap})
                    n += 1
        return n

    def hudsonrock(self):
        n = 0
        prev_all = self.state.setdefault("hudsonrock", {})
        for domain in self.p.all_domains:
            data = http(URLS["hudsonrock"], params={"domain": domain}, timeout=60)
            time.sleep(0.3)
            if not isinstance(data, dict):
                continue
            inner = data.get("data") if isinstance(data.get("data"), dict) else {}

            def field(*names):
                for c in (data, inner):
                    for k in names:
                        if c.get(k) is not None:
                            return c.get(k)
                return None
            employees = int(field("employees", "compromised_employees") or 0)
            users = int(field("users", "compromised_users") or 0)
            third = int(field("third_parties") or 0)
            last = parse_dt(field("last_employee_compromised"))
            prev = prev_all.get(domain)
            prev_all[domain] = {"employees": employees, "last": iso(last)}
            if not employees:
                continue
            if prev and employees <= prev.get("employees", 0) and iso(last) == prev.get("last"):
                continue  # nothing new since last run
            delta = employees - (prev or {}).get("employees", 0)
            if prev and delta > 0:
                title = f"{delta:,} newly reported infostealer-compromised employee(s) at {domain} ({employees:,} in total)"
            elif prev:
                title = f"New infostealer infection reported at {domain} ({employees:,} employees affected in total)"
            else:
                title = f"{employees:,} employee(s) at {domain} have had credentials stolen by infostealer malware"
            rel = self.p.relation_of(domain) or "supplier"
            self.add_signal("infostealer", "hudsonrock", domain, rel, title, "https://www.hudsonrock.com/free-tools", last,
                            (f"Most recent employee infection: {last:%b %d, %Y}. " if last else "")
                            + f"Also {users:,} customer/user accounts and {third:,} third-party accounts.",
                            {"employees": employees, "users": users, "third_parties": third})
            n += 1
        return n

    def otx(self, key):
        n, cutoff = 0, NOW - timedelta(days=max(30, self.lookback_days))
        headers = {"X-OTX-API-KEY": key}
        queries = [(d, "domain") for d in self.p.all_domains] + [(x, "name") for x in self.p.names + self.p.supplier_names]
        for q, qtype in queries:
            pulses = http(URLS["otx"], params={"q": f'"{q}"', "sort": "-modified", "limit": 10}, headers=headers).get("results", [])
            for pl in pulses:
                mod = parse_dt(pl.get("modified") or pl.get("created"))
                if not mod or mod < cutoff:
                    continue
                text = " ".join([str(pl.get("name", "")), str(pl.get("description", "")), " ".join(map(str, pl.get("tags") or [])),
                                 " ".join(map(str, pl.get("references") or []))])
                if not (mentions_domain(text, q) if qtype == "domain" else mentions_name(text, q)):
                    continue
                rel = self.p.relation_of(q)
                if rel:
                    self.add_signal("threat_report", "otx", q, rel, str(pl.get("name", "OTX pulse")),
                                    f"https://otx.alienvault.com/pulse/{pl.get('id')}", mod, str(pl.get("description", "")),
                                    {"adversary": pl.get("adversary")})
                    n += 1
        ind_cutoff = NOW - timedelta(days=7)
        for industry in self.p.industries:
            terms = [industry.lower()] + INDUSTRIES.get(industry, [])
            pulses = http(URLS["otx"], params={"q": industry.split("/")[0].split("&")[0].strip(), "sort": "-modified", "limit": 20},
                          headers=headers).get("results", [])
            kept = 0
            for pl in pulses:
                mod = parse_dt(pl.get("modified") or pl.get("created"))
                tagged = [str(i).lower() for i in (pl.get("industries") or [])]
                if not mod or mod < ind_cutoff or not any(any(t in i for t in terms) for i in tagged):
                    continue
                self.signals.append({
                    "id": fingerprint("otx-ind", pl.get("id"), industry), "kind": "threat_report",
                    "kind_label": KIND_LABELS["threat_report"], "source": "otx", "target": industry, "relation": "industry",
                    "relation_label": RELATION_LABEL["industry"], "title": str(pl.get("name", ""))[:500],
                    "detail": str(pl.get("description", ""))[:400], "url": f"https://otx.alienvault.com/pulse/{pl.get('id')}",
                    "when": mod.date().isoformat(), "observed": iso(mod), "severity": "info", "next_step": "",
                    "data": {"adversary": pl.get("adversary")},
                })
                n += 1
                kept += 1
                if kept >= 5:
                    break
        return n

    def urlhaus(self, key):
        n, cutoff = 0, NOW - timedelta(days=30)
        for domain in self.p.all_domains:
            data = http(URLS["urlhaus"], data={"host": domain}, headers={"Auth-Key": key})
            if data.get("query_status") != "ok":
                continue
            kept = 0
            for u in data.get("urls") or []:
                added = parse_dt(u.get("date_added"))
                if u.get("url_status") != "online" and (not added or added < cutoff):
                    continue
                rel = self.p.relation_of(domain) or "supplier"
                self.add_signal("malware_hosting", "urlhaus", domain, rel,
                                f"Malware URL on {domain} ({u.get('url_status', 'unknown')}): {u.get('threat') or 'malware'}",
                                u.get("urlhaus_reference") or "https://urlhaus.abuse.ch/", added,
                                f"{u.get('url', '')} — tags: {', '.join(u.get('tags') or []) or 'none'}",
                                {"status": u.get("url_status")})
                n += 1
                kept += 1
                if kept >= 5:
                    break
        return n

    def epss(self, cves):
        cves = sorted({c.upper() for c in cves if c})
        out = {}
        for i in range(0, len(cves), 100):
            data = http(URLS["epss"], params={"cve": ",".join(cves[i:i + 100])}, timeout=60)
            for row in data.get("data", []):
                try:
                    out[row["cve"].upper()] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
                except (KeyError, ValueError, TypeError):
                    pass
        return out

    def nvd_epss(self, key):
        # 1) EPSS for CVEs already in today's items
        scores = self.epss([c for it in self.items for c in (it.get("cves") or [it.get("cve")]) if c])
        for it in self.items:
            s = scores.get((it.get("cve") or "").upper())
            if s:
                it["epss"] = round(s["epss"] * 100, 1)
        # 2) New vendor CVEs EPSS predicts will be exploited, not yet in KEV
        if not self.p.vendors:
            return len(scores)
        start, fmt = NOW - timedelta(days=30), "%Y-%m-%dT%H:%M:%S.000"
        headers = {"apiKey": key} if key else {}
        pause = 0.7 if key else 6.5
        found = {}
        for vendor in self.p.vendors:
            keyword = (VENDORS.get(vendor) or [vendor.lower()])[0]
            data = http(URLS["nvd"], params={"keywordSearch": keyword, "pubStartDate": start.strftime(fmt),
                                             "pubEndDate": NOW.strftime(fmt), "resultsPerPage": 200}, headers=headers, timeout=90)
            time.sleep(pause)
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                cid = cve.get("id", "").upper()
                desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                if cid and has_term(desc, keyword):
                    found.setdefault(cid, {"vendor": vendor, "description": desc, "published": cve.get("published")})
        n = 0
        for cid, s in self.epss(found).items():
            info = found[cid]
            if cid in self.kev_cves or (s["epss"] < 0.10 and s["percentile"] < 0.95):
                continue
            self.signals.append({
                "id": fingerprint("epss", cid), "kind": "likely_exploit", "kind_label": KIND_LABELS["likely_exploit"],
                "source": "nvd_epss", "target": info["vendor"], "relation": "vendor", "relation_label": RELATION_LABEL["vendor"],
                "title": f"{cid} ({info['vendor']}) — {s['epss']:.0%} predicted chance of exploitation in the next 30 days",
                "detail": info["description"][:400], "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "when": (parse_dt(info.get("published")) or NOW).date().isoformat(), "observed": info.get("published"),
                "severity": "high" if s["epss"] >= 0.5 else "medium",
                "next_step": NEXT_STEP[("likely_exploit", "vendor")], "data": {"cve": cid, **s},
            })
            n += 1
        return n

    def mitre_attack(self, cache_path):
        if not self.p.industries:
            return 0
        groups = None
        if cache_path and os.path.exists(cache_path) and time.time() - os.path.getmtime(cache_path) < 7 * 86400:
            with open(cache_path, encoding="utf-8") as f:
                groups = json.load(f)
        if groups is None:
            bundle = http(URLS["attack"], timeout=240)
            groups = []
            for obj in bundle.get("objects", []):
                if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
                if not ref:
                    continue
                desc = obj.get("description", "")
                inds = [i for i, ts in INDUSTRIES.items() if any(has_term(desc, t) for t in [i] + ts)]
                groups.append({"name": obj.get("name", ""), "aliases": obj.get("aliases") or [], "id": ref.get("external_id"),
                               "url": ref.get("url", ""), "industries": inds})
            if cache_path:
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(groups, f)
                except OSError:
                    pass
        corpus = " ".join(f"{i['title']} {i.get('description', '')}" for i in self.items)
        corpus += " " + " ".join(f"{s['title']} {s['data'].get('group', '')} {s['data'].get('adversary', '')}" for s in self.signals)
        self.actors = []
        for g in groups:
            shared = [i for i in g["industries"] if i in self.p.industries]
            if not shared:
                continue
            hit = next((nm for nm in [g["name"]] + g["aliases"] if mentions_name(corpus, nm)), None)
            if hit:
                self.actors.append({"name": g["name"], "id": g["id"], "url": g["url"], "industries": shared, "seen_as": hit})
        self.actors = self.actors[:5]
        return len(self.actors)


# ----------------------------------------------------------------------------- assembly

def select_items(run):
    cfg, p = run.cfg, run.p
    min_risk = cfg.getint("brief", "min_risk", fallback=50)
    max_items = cfg.getint("brief", "max_items", fallback=10)
    exploited_only = truthy(cfg.get("brief", "exploited_only", fallback="no"), default=False)
    terms = p.match_terms()
    vendor_labels = set(p.vendors)
    selected = []
    seen = set()
    for it in run.items:
        key = (it.get("cve") or it["title"]).lower()
        if key in seen:
            continue
        seen.add(key)
        text = f"{it['title']} {it.get('description', '')} {it.get('vendor_project', '')}"
        matched = sorted({label for label, term in terms if has_term(text, term)})
        it["matched"] = matched
        it["in_stack"] = [m for m in matched if m in vendor_labels]
        if exploited_only and not it.get("exploited"):
            continue
        if matched or it["risk"] >= min_risk:
            selected.append(it)
    selected.sort(key=lambda i: (-(len(i["in_stack"]) > 0), -(len(i["matched"]) > 0), -i["risk"], -(i.get("epss") or 0)))
    return selected[:max_items], len(selected)


def build_alerts(signals):
    signals.sort(key=lambda a: a["when"], reverse=True)
    grouped, order = {}, []
    for a in signals:
        k = (a["relation"], a["kind"], a["target"]) if a["kind"] == "threat_report" else a["id"]
        if k not in grouped:
            a["more"], a["more_titles"] = 0, []
            grouped[k] = a
            order.append(k)
        else:
            g = grouped[k]
            if a["title"] != g["title"] and a["title"] not in g["more_titles"]:
                g["more_titles"].append(a["title"])
            g["more"] = len(g["more_titles"])
            if SEVERITY_RANK[a["severity"]] < SEVERITY_RANK[g["severity"]]:
                g["severity"] = a["severity"]
    alerts = [grouped[k] for k in order]
    alerts.sort(key=lambda a: SEVERITY_RANK[a["severity"]])
    shown = [a for a in alerts if a["severity"] != "info"][:15]
    shown += [a for a in alerts if a["severity"] == "info"][:max(0, 15 - len(shown))][:5]
    return shown, alerts


def assess(selected, alerts, vendors):
    level, drivers = 1, []

    def bump(n, reason):
        nonlocal level
        level = max(level, n)
        if reason not in [d for _, d in drivers]:
            drivers.append((n, reason))
    for a in alerts:
        if a["severity"] == "critical":
            bump(5, f"{a['kind_label']}: {a['target']}")
        elif a["severity"] == "high" and a["relation"] == "own":
            bump(4, f"{a['kind_label']}: {a['target']}")
        elif a["severity"] == "high" and a["relation"] == "vendor":
            bump(4, a["title"].split(" — ")[0] if a["kind"] == "likely_exploit" else a["title"])
        elif a["severity"] == "high" and a["relation"] == "supplier":
            bump(3, f"Supplier {a['target']}: {a['kind_label'].lower()}")
        elif a["severity"] == "medium" and a["relation"] in ("own", "supplier"):
            bump(2, f"{a['relation_label']} {a['target']}: {a['kind_label'].lower()}")
    kev_new = 0
    for it in selected:
        exploited = it.get("exploited") or it["source"] == "kev"
        kev_new += it["source"] == "kev"
        ref = it.get("cve") or it["title"][:60]
        if exploited and it["in_stack"]:
            bump(4, f"Actively exploited in your stack ({', '.join(it['in_stack'])}): {ref}")
        elif exploited and it["matched"]:
            bump(3, f"Exploited item matching {', '.join(it['matched'][:2])}: {ref}")
        elif it["risk"] >= 70:
            bump(2, f"High-risk item in today's feeds: {it['title'][:70]}")
    if kev_new >= 3:
        bump(3, f"{kev_new} new CISA KEV entries")
    name, color, posture, tint = LEVELS[level]
    drivers.sort(key=lambda d: -d[0])
    return {"level": level, "name": name, "color": color, "posture": posture, "tint": tint,
            "scale": [{"n": n, "name": v[0], "color": v[1], "active": n == level} for n, v in LEVELS.items()],
            "drivers": [d for _, d in drivers[:4]]}


def fallback_key_risks(selected, alerts):
    ranked = []
    for a in alerts:
        if a["severity"] in ("critical", "high"):
            rank = 5 if a["severity"] == "critical" else (3 if a["relation"] == "supplier" else 4)
            ranked.append((rank, {"risk": a["title"], "why": f"{a['relation_label']} · {a['kind_label']}", "link": a["url"]}))
    for it in selected:
        if (it.get("exploited") or it["source"] == "kev") and it["matched"]:
            why = "Actively exploited · " + (f"in your stack ({', '.join(it['in_stack'])})" if it["in_stack"]
                                             else f"matches {', '.join(it['matched'][:2])}")
            ranked.append((4 if it["in_stack"] else 3, {"risk": it["title"], "why": why, "link": it["url"]}))
    if len(ranked) < 3:
        for it in selected:
            why = ("On CISA's Known Exploited Vulnerabilities list: attackers are already using it" if it["source"] == "kev"
                   else ("Reported as actively exploited" if it.get("exploited") else f"High-risk item from {it['source_name']}")
                   + f" (risk {it['risk']}/100)")
            ranked.append((1, {"risk": it["title"], "why": why, "link": it["url"]}))
    ranked.sort(key=lambda r: -r[0])
    out, seen = [], set()
    for _, r in ranked:
        if r["risk"] not in seen:
            seen.add(r["risk"])
            out.append(r)
    return out[:3]


def import_extra(run, path):
    """Merge findings gathered outside this script. Format:
    {"sources_checked": {"kev": "via web fetch", ...},
     "items":   [{"source": "kev|cisa_news|hacker_news", "title": "...", "url": "...", "description": "...",
                  "cve": "CVE-...", "published": "YYYY-MM-DD", "exploited": true, "ransomware": false}],
     "signals": [{"kind": "leak_site|lookalike_domain|infostealer|threat_report|malware_hosting|likely_exploit",
                  "source": "ransomlook|crtsh|hudsonrock|otx|urlhaus|nvd_epss", "target": "name or domain from config",
                  "title": "...", "url": "...", "observed": "YYYY-MM-DD", "detail": "...", "data": {}}]}
    Severity and relation are worked out here by the same rules as fetched data; nothing is taken on trust."""
    with open(path, encoding="utf-8") as f:
        extra = json.load(f)
    for key, how in (extra.get("sources_checked") or {}).items():
        if key in SOURCE_NAMES:
            run.sources = [x for x in run.sources if x["key"] != key]
            run.status(key, "ok", f"checked {how}")
    for it in extra.get("items") or []:
        src = it.get("source") if it.get("source") in ("kev", "cisa_news", "hacker_news") else "hacker_news"
        title = str(it.get("title") or "").strip()
        if not title:
            continue
        cve = str(it.get("cve") or "").upper()
        if src == "kev" and cve:
            run.kev_cves.add(cve)
        run.items.append({
            "source": src, "source_name": SOURCE_NAMES[src], "title": title, "url": it.get("url", ""),
            "description": str(it.get("description") or "")[:1500], "cve": cve, "cves": [cve] if cve else [],
            "published": it.get("published"), "exploited": bool(it.get("exploited")) or src == "kev",
            "ransomware": bool(it.get("ransomware")), "risk": risk_score(src, title),
            "vendor_project": it.get("vendor_project", ""),
            "epss": round(float(it["epss"]) * 100, 1) if isinstance(it.get("epss"), (int, float)) and it["epss"] <= 1 else None,
        })
    for sg in extra.get("signals") or []:
        kind, target = sg.get("kind"), str(sg.get("target") or "").strip()
        if kind not in KIND_LABELS or not target:
            continue
        rel = "vendor" if kind == "likely_exploit" else run.p.relation_of(normalize_domain(target) if "." in target else target)
        if not rel:
            log(f"--add: skipped signal for '{target}' (not a company, supplier or technology in config)")
            continue
        data = sg.get("data") or {}
        if kind == "likely_exploit":
            sev = "high" if float(data.get("epss", 0) or 0) >= 0.5 else "medium"
            run.signals.append({
                "id": fingerprint("add", kind, target, sg.get("title")), "kind": kind, "kind_label": KIND_LABELS[kind],
                "source": sg.get("source", "nvd_epss"), "target": run.p.display(target), "relation": rel,
                "relation_label": RELATION_LABEL[rel], "title": str(sg.get("title", ""))[:500],
                "detail": str(sg.get("detail") or "")[:400], "url": sg.get("url", ""),
                "when": str(sg.get("observed") or NOW.date().isoformat())[:10], "observed": sg.get("observed"),
                "severity": sev, "next_step": NEXT_STEP[("likely_exploit", "vendor")], "data": data})
        else:
            run.add_signal(kind, sg.get("source", "web"), normalize_domain(target) if "." in target else target, rel,
                           str(sg.get("title", "")), sg.get("url", ""), parse_dt(sg.get("observed")), sg.get("detail", ""), data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default="brief.json")
    ap.add_argument("--state", default="", help="Optional JSON file kept between runs (avoids repeating infostealer counts)")
    ap.add_argument("--cache-dir", default="", help="Optional folder to cache the MITRE ATT&CK download (7 days)")
    ap.add_argument("--add", default="", help="JSON of items/signals gathered another way (e.g. Claude's web tools); see SKILL.md")
    ap.add_argument("--no-fetch", default="", help="Comma-separated source keys not to fetch (e.g. ones already known to be blocked); 'all' = none")
    args = ap.parse_args()

    cfg = load_config(args.config)
    p = Profile(cfg)
    state = {}
    if args.state and os.path.exists(args.state):
        try:
            with open(args.state, encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = {}
    run = Run(cfg, p, state)
    run.actors = []
    keys = {k: get_key(cfg, k) for k in KEY_ENV}

    no_fetch = set(split_list(args.no_fetch))
    if no_fetch:
        orig = run.guard

        def guard(key, fn, need=None, missing=""):
            if "all" in no_fetch or key in no_fetch:
                return None  # status is filled from --add below, or marked not checked
            return orig(key, fn, need, missing)
        run.guard = guard

    run.guard("kev", run.kev)
    run.guard("cisa_news", lambda: run.rss("cisa_news"))
    run.guard("hacker_news", lambda: run.rss("hacker_news"))
    has_watch = bool(p.all_domains or p.names or p.supplier_names)
    run.guard("ransomlook", run.ransomlook, has_watch, "no company names or domains in [profile] / [suppliers]")
    run.guard("crtsh", run.crtsh, bool(p.domains), "no company domains in [profile]")
    run.guard("hudsonrock", run.hudsonrock, bool(p.all_domains), "no domains in [profile] / [suppliers]")
    run.guard("otx", lambda: run.otx(keys["otx_api_key"]), bool(keys["otx_api_key"]),
              "no API key: add otx_api_key in [keys] or CISO_BRIEF_OTX_API_KEY (free at otx.alienvault.com)")
    run.guard("urlhaus", lambda: run.urlhaus(keys["abusech_auth_key"]), bool(keys["abusech_auth_key"]) and bool(p.all_domains),
              "no Auth-Key: add abusech_auth_key in [keys] or CISO_BRIEF_ABUSECH_AUTH_KEY (free at auth.abuse.ch)"
              if not keys["abusech_auth_key"] else "no domains to check")
    run.guard("nvd_epss", lambda: run.nvd_epss(keys["nvd_api_key"]))
    cache = os.path.join(args.cache_dir, "attack_groups.json") if args.cache_dir else ""
    run.guard("mitre_attack", lambda: run.mitre_attack(cache), bool(p.industries), "no industries in [profile]")

    if args.add:
        import_extra(run, args.add)
    if no_fetch:
        done = {x["key"] for x in run.sources}
        for key in SOURCE_NAMES:
            if key not in done and ("all" in no_fetch or key in no_fetch):
                keyname = {"otx": "otx_api_key", "urlhaus": "abusech_auth_key"}.get(key)
                if keyname and not keys[keyname]:
                    run.status(key, "skipped", f"no API key ({keyname} in [keys])")
                elif not run.enabled(key):
                    run.status(key, "skipped", "turned off in config")
                else:
                    run.status(key, "failed", "not checked: blocked here and not fetched another way")

    selected, matched_total = select_items(run)
    shown, alerts = build_alerts(run.signals)
    condition = assess(selected, alerts, p.vendors)
    sections = split_list(cfg.get("brief", "sections", fallback="summary, early_warning, actions, themes, attacks, vendors, items"))
    kev_items = [i for i in run.items if i["source"] == "kev"]
    vendors = [{"vendor": v, "items": [i for i in selected if v in i["in_stack"]][:5]} for v in p.vendors]
    ok = [s for s in run.sources if s["status"] == "ok"]
    blocked = [s for s in run.sources if "network blocked" in s["detail"]]
    credits = sorted({s["name"] for s in ok})
    brief = {
        "generated_at": NOW.isoformat(), "date": NOW.date().isoformat(), "lookback_days": run.lookback_days,
        "profile": p.as_dict(), "sections": sections,
        "condition": condition,
        "key_risks_fallback": fallback_key_risks(selected, alerts),
        "early_warning": {
            "alerts": shown, "more": max(0, len(alerts) - len(shown)),
            "critical": sum(1 for a in alerts if a["severity"] == "critical"),
            "high": sum(1 for a in alerts if a["severity"] == "high"),
            "actors": run.actors, "has_watchlist": has_watch,
        },
        "items": selected, "kev": kev_items[:10], "vendors": vendors,
        "stats": {"analyzed": len(run.items), "included": matched_total,
                  "high": sum(1 for i in selected if i["risk"] >= 70), "shown": len(selected)},
        "sources": run.sources, "credits": credits,
        # Sources this environment's network refused. SKILL.md tells Claude to try its own web tools for these.
        "blocked_sources": [s["key"] for s in blocked],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(brief, f, indent=1, ensure_ascii=False)
    if args.state:
        try:
            with open(args.state, "w", encoding="utf-8") as f:
                json.dump(run.state, f)
        except OSError as e:
            log(f"could not save state: {e}")
    c = condition
    log(f"\nThreat condition: {c['name']} ({c['level']}/5). Items: {len(selected)} shown of {matched_total} relevant, "
        f"{len(run.items)} reviewed. Alerts: {len(alerts)}. Sources ok: {len(ok)}/{len(run.sources)}. Wrote {args.out}")
    if blocked:
        log(f"NOTE: {len(blocked)} source(s) blocked by this environment's network: {', '.join(s['key'] for s in blocked)}. "
            "See 'If sources are blocked' in SKILL.md.")


if __name__ == "__main__":
    main()
