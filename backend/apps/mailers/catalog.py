"""
Picklists for the mailer builder. Each entry maps a display label to the
whole-word terms used to match threat items (see intelligence.tasks.has_keyword).
"""

SECTIONS = [
    ("summary", "Threat condition & executive summary"),
    ("early_warning", "Early warning: your company, suppliers & industry"),
    ("actions", "Immediate actions"),
    ("themes", "Top themes"),
    ("attacks", "Active attacks in the wild"),
    ("kev", "New CISA KEV entries"),
    ("vendors", "Your vendor watchlist"),
    ("items", "Top items by risk"),
]
SECTION_KEYS = [k for k, _ in SECTIONS]
SECTION_LABELS = dict(SECTIONS)
AI_SECTIONS = {"summary", "actions", "themes", "attacks"}
DEFAULT_SECTIONS = ["summary", "early_warning", "actions", "themes", "attacks", "vendors", "items"]

AUDIENCES = [
    ("executive", "Executive / Board — business risk, plain language"),
    ("technical", "Technical / SOC — CVEs, products, patch & detection steps"),
]

FREQUENCIES = [("daily", "Daily"), ("weekly", "Weekly")]
WEEKDAYS = [(0, "Monday"), (1, "Tuesday"), (2, "Wednesday"), (3, "Thursday"), (4, "Friday"), (5, "Saturday"), (6, "Sunday")]
HOURS = [(h, f"{(h % 12) or 12}:00 {'AM' if h < 12 else 'PM'}") for h in range(24)]
TIMEZONES = [(tz, tz) for tz in (
    "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "UTC", "Europe/London",
)]

SOURCES = [
    ("kev", "CISA Known Exploited Vulnerabilities"),
    ("cisa_news", "CISA News"),
    ("hacker_news", "The Hacker News"),
]
SOURCE_KEYS = [k for k, _ in SOURCES]

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

VENDOR_CHOICES = [(v, v) for v in VENDORS]
INDUSTRY_CHOICES = [(i, i) for i in INDUSTRIES]


def normalize_industries(values):
    """Map free-text industries onto catalog names (case-insensitive, also by match term).
    Returns (industries, leftover_keywords)."""
    by_name = {k.lower(): k for k in INDUSTRIES}
    by_term = {t: k for k, terms in INDUSTRIES.items() for t in terms}
    industries, leftovers = [], []
    for v in values or []:
        key = str(v).strip()
        hit = by_name.get(key.lower()) or by_term.get(key.lower())
        if hit and hit not in industries:
            industries.append(hit)
        elif key and not hit:
            leftovers.append(key)
    return industries, leftovers


VENDOR_GROUPS = [
    ("Cloud & infrastructure", ["Microsoft", "AWS", "Google", "VMware / Broadcom", "Cisco", "Fortinet", "Palo Alto Networks",
                                "SonicWall", "Juniper", "Citrix / NetScaler", "Ivanti", "Linux / Open source"]),
    ("Identity & enterprise SaaS", ["Okta", "Apple", "Atlassian", "Oracle", "SAP", "Veeam", "ConnectWise"]),
    ("Construction & engineering software", ["Procore", "Autodesk", "Trimble", "Bentley Systems"]),
    ("Industrial controls / OT", ["Siemens (ICS)", "Rockwell (ICS)", "Schneider Electric (ICS)"]),
]

# Shown under each module in the builder: (subtitle, badge style)
SECTION_META = {
    "summary": ("Alert level · today's key risks · AI synthesis", "ai"),
    "early_warning": ("Watchlist alert feed", "cyan"),
    "actions": ("AI-prioritized playbook", "ai"),
    "themes": ("Clustered intel", "ai"),
    "attacks": ("CISA KEV verified", "crit"),
    "kev": ("Direct from CISA", "crit"),
    "vendors": ("Matched perimeter assets", "cyan"),
    "items": ("Global feed intelligence", ""),
}

AUDIENCE_CARDS = {
    "executive": ("Executive & Board", "Business impact in plain language, risk framed for leadership, actions assigned to owners.", "Strategic · Risk-weighted"),
    "technical": ("Technical & SOC", "CVE IDs, affected products, exploitation status, EPSS, and concrete patch / detection steps.", "Forensic · Operational"),
}
