# Fetching blocked sources with web tools

Use this when `brief.json` lists sources in `blocked_sources`. Fetch only those, with your web fetch tool,
then write `extra.json` and re-run `collect.py --no-fetch all --add extra.json` (see SKILL.md step 2).

`N` = `lookback_days` from the settings. "Watched" = the company names/domains in `[profile]` and the
supplier names/domains in `[suppliers]`. Match whole words and whole domains only ("okta" ≠ "Oktoberfest").

| Key | What to fetch | What to keep |
|---|---|---|
| `kev` | https://www.cisa.gov/known-exploited-vulnerabilities-catalog (or the JSON feed https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Entries with **date added** in the last max(2, N+1) days: CVE, vendor/product, name, short description, whether ransomware use is "Known" → `items` with `"source": "kev"` |
| `cisa_news` | https://www.cisa.gov/news.xml | Items published in the last N days → `items` with `"source": "cisa_news"` |
| `hacker_news` | https://feeds.feedburner.com/TheHackersNews | Items from the last N days → `items` with `"source": "hacker_news"`; set `"exploited": true` only if the text says actively exploited / exploited in the wild |
| `ransomlook` | https://www.ransomlook.io/api/posts?days=3 (or https://www.ransomlook.io/recent) | Posts whose title/description names a watched company or domain → `signals` with `"kind": "leak_site"`, `"target"` = that name/domain, title "<post title> — claimed by <group>" |
| `crtsh` | https://crt.sh/?q=%25LABEL%25&output=json&exclude=expired&deduplicate=Y where LABEL is the company domain without its ending (ridgelinebuilders.com → ridgelinebuilders; skip if under 5 letters) | Certificates issued in the last 14 days for hosts **not** on the company's own domains → `signals` `"kind": "lookalike_domain"`, `"target"` = the company domain, `"data": {"phishy": [...words like login, sso, secure, vpn, payroll...], "tld_swap": true if same name on another ending}` |
| `hudsonrock` | https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=DOMAIN for each watched domain | If employees > 0 → `signals` `"kind": "infostealer"`, title "N employee(s) at DOMAIN have had credentials stolen by infostealer malware", `"observed"` = last_employee_compromised |
| `nvd_epss` | https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2 for CVEs in your items | Put `"epss"` (0–1) in `signals` of kind `likely_exploit` only for new vendor CVEs not in KEV with EPSS ≥ 0.10; otherwise skip |
| `mitre_attack` | Skip in fallback (50 MB file). | — |
| `otx`, `urlhaus` | Need an API key sent in a header, which web fetch can't do. Skip; they stay "not checked". | — |

If a page won't load or the tool declines it, skip that source. Don't substitute news articles or guesses.

## extra.json format

```json
{
  "sources_checked": {"kev": "via web fetch", "ransomlook": "via web fetch"},
  "items": [
    {"source": "kev", "title": "CVE-2026-1111 — Fortinet FortiOS Heap Overflow", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
     "description": "short description", "cve": "CVE-2026-1111", "published": "2026-11-19", "vendor_project": "Fortinet FortiOS",
     "exploited": true, "ransomware": true}
  ],
  "signals": [
    {"kind": "leak_site", "source": "ransomlook", "target": "Trimble", "title": "Trimble Inc. — claimed by akira",
     "url": "https://www.ransomlook.io/group/akira", "observed": "2026-11-19", "detail": ""}
  ]
}
```

List in `sources_checked` only sources you actually fetched (even if they had nothing relevant).
`target` must be a company, supplier, domain or technology from the settings; anything else is dropped.
Severity, relation and the threat condition are computed by `collect.py`, not by you.
