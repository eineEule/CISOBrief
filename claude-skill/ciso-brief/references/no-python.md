# Running the brief without Python

Use only when no code can run in this environment. Gather data with web fetch as in `fallback.md`, then apply these
rules yourself, exactly. Output the brief as Markdown in the chat (and as an email through a connector if
`[delivery] mode = email`). Say at the top that it was built in limited mode and list sources not checked.

## Matching

An item is **relevant** if its title/description contains, as a whole word or phrase, any of: a technology term
(built-in vendor names expand to their products, e.g. Microsoft → windows, exchange, azure, entra, outlook, sharepoint,
defender), an industry term, a keyword, or a company/supplier name. Unmatched items are kept only if risk ≥ `min_risk`.

**Risk score** (0–95): KEV entries = 95. Otherwise start at 40; +30 ransomware; +25 zero-day/0-day;
+25 actively exploited / exploited in the wild; +20 critical; +15 remote code execution/RCE; cap at 95.

## Early-warning severity

| Kind | Your company | Supplier | Other |
|---|---|---|---|
| Named on a ransomware leak site | critical | high | — |
| Domain hosting malware (URLhaus) | critical | high | — |
| Lookalike domain certificate | high if phishing words or same name on another ending, else medium | — | — |
| Infostealer employees | high if last infection ≤ 90 days ago, else medium | medium if ≤ 90 days, else info | — |
| Community threat report | high | medium | info (industry) |
| Vendor CVE likely exploited (not in KEV) | high if EPSS ≥ 50%, else medium (relation: your technology) | | |

## Threat condition (take the highest level that applies)

- **5 SEVERE** (Respond now): any critical alert.
- **4 HIGH** (Act today): a high alert about your company; a high likely-exploit alert for your technology;
  an actively exploited / KEV item that matches your technology.
- **3 ELEVATED** (Heightened vigilance): a high alert about a supplier; an exploited item matching your industry,
  keywords or names; 3 or more new KEV entries among relevant items.
- **2 GUARDED** (Stay attentive): a medium alert about your company or a supplier; any relevant item with risk ≥ 70.
- **1 LOW** (Routine monitoring): none of the above.

List up to 4 reasons ("drivers") that set the level, highest first.

## Key risks (if you can't rank by judgment)

Critical alerts first, then high alerts about your company, then exploited items in your technology, then high alerts
about suppliers and exploited items matching other terms, then the highest-risk remaining items. Top 3.

Then write the narrative following SKILL.md step 3.
