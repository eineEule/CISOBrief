---
name: ciso-brief
description: Build a CISO Brief, a threat-intel briefing with a LOW-to-SEVERE threat condition, today's key risks and early warnings about the user's company, suppliers, technology and industry, from free open sources (CISA KEV, RansomLook, crt.sh, Hudson Rock, NVD/EPSS, MITRE ATT&CK, optional OTX and URLhaus). Use when the user asks for their CISO brief, threat brief, daily/weekly security briefing, or to set one up or schedule it.
---

# CISO Brief

Produce a threat-intel brief for one organization, written for its board/executives or its SOC, from free sources.
The scripts do the fetching, matching and scoring; **you** write the narrative and deliver it.

Two rules matter more than anything else here:
- **The threat condition comes from the rules, never from your judgment.** Use `condition.level` from `brief.json` as is.
  You explain it; you don't raise or lower it.
- **Only state what the data shows.** Every risk, number, CVE and company you mention must be in `brief.json`.
  Leak-site posts are criminals' claims until confirmed; say so.

Paths below are relative to this skill's folder (where this file is). `SKILL_DIR` means that folder.

## 1. Find or create the settings

Look for the user's settings in this order and use the first that exists:
1. a `ciso-brief.ini` in the current working folder (or one the user names);
2. `SKILL_DIR/config.ini`.

If neither exists, or it still says `company = Example Corp`, set one up with the user before anything else.
Ask in one message (skip anything they already told you):
- company name, other names it goes by, and its domains;
- industry (or industries);
- the main technology they run (vendors/products);
- key suppliers and partners, with their domains;
- audience: **executive** (board, plain language) or **technical** (SOC: CVEs, EPSS, patch/detection steps);
- daily or weekly.

Then copy `SKILL_DIR/config.example.ini` to `ciso-brief.ini` in the working folder (the skill folder may be read-only)
and fill it in. Leave `[keys]` blank and `[delivery] mode = chat` unless the user asks otherwise; mention in one line
that free API keys (OTX, abuse.ch, NVD) add more early-warning sources and email delivery can be turned on later.
Never paste API keys or passwords back into the chat; if the user gives one, write it into the file only.

## 2. Collect

Make an output folder, e.g. `ciso-brief-out/` in the working folder. If the working folder persists between runs,
also pass `--state` and `--cache-dir` there (avoids repeating old infostealer counts; caches the 50 MB MITRE file for 7 days).

```bash
python3 SKILL_DIR/scripts/collect.py --config ciso-brief.ini --out ciso-brief-out/brief.json \
        --state ciso-brief-out/state.json --cache-dir ciso-brief-out
```

(Use `python` if `python3` isn't found. Python 3.9+, standard library only; nothing to install.)
Read `brief.json`. Each entry in `sources` has `status` ok / skipped / failed and a reason.

### If sources are blocked

Some environments only allow a few websites from code. `blocked_sources` in `brief.json` lists the sources this
environment refused. If it's empty, go to step 3. Otherwise, fetch those sources with your own web tools (web fetch /
web search), using the URLs and filters in `references/fallback.md`, and write what you find to
`ciso-brief-out/extra.json` in the format shown there. Then re-run without fetching, so the rules score your findings
exactly like fetched data:

```bash
python3 SKILL_DIR/scripts/collect.py --config ciso-brief.ini --out ciso-brief-out/brief.json \
        --no-fetch all --add ciso-brief-out/extra.json
```

Only include findings you actually saw in a fetched page, with its URL. A source you couldn't reach stays "not checked";
the brief lists it. **If Python can't run at all**, follow `references/no-python.md` instead.

## 3. Write the narrative

Write `ciso-brief-out/narrative.json` (all fields optional; omit a section rather than pad it):

```json
{
  "headline": "One line: the most important thing today, no brief name or date",
  "condition_rationale": "1–2 sentences on why the level is what it is, from condition.drivers",
  "key_risks": [{"risk": "short title", "why": "why it matters to THIS company", "link": "url from brief.json"}],
  "summary": "3–5 sentences",
  "actions": ["Action — owner — timeframe"],
  "themes": [{"theme": "...", "why_it_matters": "..."}],
  "attacks": [{"title": "...", "link": "...", "actor": "...", "why_it_matters": "..."}]
}
```

Source material, in priority order: `condition` (level + drivers), `early_warning.alerts` (critical/high first),
`items` with `in_stack` or `exploited`, `early_warning.actors`, then the rest of `items`.

- **key_risks**: exactly the top 3, most urgent first. Start from `key_risks_fallback`; reword for the audience and
  say why each matters to this company (their supplier, their VPN, their domain). Keep the links.
- **actions**: 3–5, concrete, each with an owner role and a timeframe that fits the level
  (SEVERE/HIGH: today/24h; ELEVATED: this week; GUARDED/LOW: next cycle). Use each alert's `next_step` as a base.
- **attacks**: only exploited items or alerts from the data; `actor` only if the source names one, else "Unknown".
- **executive** audience: business impact in plain language; no CVE lists, no scores without meaning
  ("attackers are already using it", not "EPSS 0.94"); 3 sentences beat 10.
- **technical** audience: CVE IDs, affected products/versions, KEV status, EPSS %, patch/mitigation and detection ideas.
- Quiet day (LOW, few items): say so plainly in a short brief. Never invent urgency.
- Infostealer counts and leak-site posts are third-party claims: "reported", "claimed", not "confirmed".

## 4. Render

```bash
python3 SKILL_DIR/scripts/render.py --brief ciso-brief-out/brief.json --narrative ciso-brief-out/narrative.json \
        --out-dir ciso-brief-out --logo data
```

This writes `brief.html` (email-ready), `brief.md` and `subject.txt`. Use `--logo cid` before sending by SMTP,
and `--logo url` before handing the HTML to an email connector (embedded images are stripped by Gmail/Outlook APIs).

## 5. Deliver

Read `[delivery]` in the settings. Email is **off unless the settings turn it on**.

- `mode = chat` (default): reply with the subject line, the threat condition and the 3 key risks, then share
  `brief.html` (send it as a file if you have a tool for that) and offer the full brief. Keep the reply short.
- `mode = file`: save the files and tell the user where they are.
- `mode = email`, `email_method = connector`: find the user's connected Gmail or Outlook tools. Render with
  `--logo url`, then create a message with subject = `subject.txt`, HTML body = `brief.html`, to = `recipients`
  (blank = the user's own address). `connector_action = draft` (default): create a **draft** and say it's ready to review.
  `connector_action = send`: send it; the user chose this in their settings. If no email connector is available,
  say so in one line and fall back to `chat`.
- `mode = email`, `email_method = smtp`: render with `--logo cid`, then
  ```bash
  python3 SKILL_DIR/scripts/send_email.py --config ciso-brief.ini --html ciso-brief-out/brief.html \
          --text ciso-brief-out/brief.md --subject-file ciso-brief-out/subject.txt
  ```
  If it fails (blocked network, bad password), report the one-line error and fall back to `chat`.

Always end by naming any sources that were not checked (from `sources`), in one line.

## Scheduling

When the user asks for this on a schedule ("every weekday at 7am", "Mondays at 8"), create a scheduled task
(use the scheduled-task tools available in this session) whose prompt is self-contained, for example:
"Run the ciso-brief skill using the settings in <full path to ciso-brief.ini> and deliver it as configured."
Use `lookback_days = 1` for daily and `7` for weekly in the settings. Each scheduled run starts fresh, so keep the
settings file somewhere the run can reach.

## Files

- `config.example.ini`: all settings, commented. Copy to `ciso-brief.ini`.
- `scripts/collect.py`: fetch, match, score, threat condition → `brief.json`. `--help` for options.
- `scripts/render.py`: `brief.json` + `narrative.json` → `brief.html`, `brief.md`, `subject.txt`.
- `scripts/send_email.py`: optional SMTP sender (`--dry-run` to test).
- `references/fallback.md`: fetching blocked sources with web tools; `extra.json` format.
- `references/no-python.md`: the full rules, for when no code can run.
- `assets/logo-email.png`: logo used in the email header.
