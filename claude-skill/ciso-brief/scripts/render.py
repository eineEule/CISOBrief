#!/usr/bin/env python3
"""
Render the brief as an email-ready HTML file and a plain-text/Markdown version.

    python render.py --brief brief.json [--narrative narrative.json] [--out-dir .] [--logo data|cid|url|none]

narrative.json is the written part (by Claude, or any AI, or by hand). Every field is optional;
without it the brief still renders from the rules-based data:
{
  "headline": "...",
  "condition_rationale": "One or two sentences on why today's level is what it is.",
  "key_risks": [{"risk": "...", "why": "...", "link": "https://..."}],
  "summary": "...",
  "actions": ["..."],
  "themes": [{"theme": "...", "why_it_matters": "..."}],
  "attacks": [{"title": "...", "link": "https://...", "actor": "...", "why_it_matters": "..."}]
}
Writes brief.html, brief.md and subject.txt. Standard library only.
"""
import argparse
import base64
import json
import os
from html import escape as e

LOGO_URL = "https://raw.githubusercontent.com/eineEule/CISOBrief/main/docs/images/logo.png"
LOGO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "logo-email.png")
SEV_COLORS = {"critical": ("#b42318", "#fef3f2", "#b42318"), "high": ("#dc6803", "#fffaeb", "#b54708"),
              "medium": ("#0b5cad", "#fafbfc", "#0b5cad"), "info": ("#d0d5dd", "#fafbfc", "#0b5cad")}
FONT = "Segoe UI,Arial,sans-serif"


def a(url, text, style="color:#0b5cad"):
    return f'<a href="{e(url)}" style="{style}">{e(text)}</a>' if url else e(text)


def why_br(text):
    return '<br><span style="color:#5b6470;font-size:13px">' + e(text) + "</span>" if text else ""


def exploited_tag(flag):
    return ' <span style="color:#b42318;font-size:12px">exploited</span>' if flag else ""


def epss_tag(v):
    return ' <span style="color:#5b6470;font-size:12px">EPSS ' + str(v) + "%</span>" if v is not None else ""


def matches_tag(m):
    return '<br><span style="color:#5b6470;font-size:12px">Matches: ' + e(", ".join(m)) + "</span>" if m else ""


def risk_link(r):
    if r.get("link"):
        return a(r["link"], r.get("risk", ""), "color:#1b1f24;font-weight:700;text-decoration:underline")
    return "<strong>" + e(r.get("risk", "")) + "</strong>"


def logo_src(mode):
    if mode == "cid":
        return "cid:cisobrief-logo"
    if mode == "url":
        return LOGO_URL
    if mode == "data" and os.path.exists(LOGO_FILE):
        with open(LOGO_FILE, "rb") as f:
            return "data:image/png;base64," + base64.b64encode(f.read()).decode()
    return ""


def subject(brief, n):
    c = brief["condition"]
    tags = [c["name"]] if "summary" in brief["sections"] else []
    if brief["early_warning"].get("critical") or c["level"] == 5:
        tags.append("Action needed")
    prefix = f"[{' · '.join(tags)}] " if tags else ""
    name = brief["profile"]["brief_name"]
    head = (n.get("headline") or "").strip()
    while head.lower().startswith(name.lower()):
        head = head[len(name):].lstrip(" :—-–").strip()
    return (prefix + f"{name}: {head or c['name'].title() + ' threat condition'}")[:200]


def condition_html(brief, n):
    c = brief["condition"]
    scale = "".join(
        f'<td width="44" height="10" style="background:{s["color"] if s["n"] <= c["level"] else "#e5e7eb"};border-radius:2px"></td>'
        for s in c["scale"])
    labels = "".join(
        f'<td align="center" style="font:600 8px/12px {FONT};color:{s["color"] if s["active"] else "#9aa3ad"}">{s["name"]}</td>'
        for s in c["scale"])
    risks = n.get("key_risks") or brief["key_risks_fallback"]
    rows = "".join(
        f'<tr><td valign="top" width="26" style="padding:4px 0;font:800 15px/20px {FONT};color:{c["color"]}">{i}</td>'
        f'<td style="padding:4px 0;font:400 14px/20px {FONT};color:#1b1f24">'
        f'{risk_link(r)}{why_br(r.get("why"))}</td></tr>'
        for i, r in enumerate(risks[:3], 1))
    rationale = n.get("condition_rationale", "")
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:4px 0 18px;background:{c['tint']};border:1px solid {c['color']}33;border-left:6px solid {c['color']};border-radius:6px">
<tr><td style="padding:14px 16px">
 <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse"><tr>
  <td valign="middle">
   <div style="font:700 11px/14px {FONT};letter-spacing:.12em;color:#5b6470;text-transform:uppercase">Threat condition · {e(brief['date'])}</div>
   <div style="font:800 30px/36px {FONT};color:{c['color']}">{c['name']} <span style="font:600 14px {FONT};color:#1b1f24">— {e(c['posture'])}</span></div>
  </td>
  <td valign="middle" align="right" width="240"><table role="presentation" cellpadding="0" cellspacing="2" style="border-collapse:separate"><tr>{scale}</tr><tr>{labels}</tr></table></td>
 </tr></table>
 {f'<p style="margin:10px 0 0;font:400 14px/20px {FONT};color:#1b1f24">{e(rationale)}</p>' if rationale else ''}
 {f'<p style="margin:8px 0 0;font:400 12px/18px {FONT};color:#5b6470"><strong style="color:#1b1f24">Why:</strong> {e(" · ".join(c["drivers"]))}</p>' if c['drivers'] else ''}
 {f'<div style="margin:14px 0 6px;font:700 11px/14px {FONT};letter-spacing:.12em;color:#5b6470;text-transform:uppercase">Today&#39;s key risks</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">{rows}</table>' if rows else ''}
</td></tr></table>"""


def h2(t):
    return f'<h2 style="font-size:16px;margin:18px 0 6px">{e(t)}</h2>'


def section_html(key, brief, n):
    ew = brief["early_warning"]
    if key == "summary" and n.get("summary"):
        return f'<p style="margin:0 0 16px">{e(n["summary"])}</p>'
    if key == "early_warning":
        out = []
        if ew["alerts"] or ew["actors"] or not ew["has_watchlist"]:
            out.append(h2("Early warning"))
        if not ew["has_watchlist"]:
            out.append('<p style="margin:0;color:#5b6470">Add your company names, domains and key suppliers to config.ini to get alerts here.</p>')
        for al in ew["alerts"]:
            bar, bg, fg = SEV_COLORS[al["severity"]]
            more = (f'<div style="font-size:12px;color:#5b6470">+ {al["more"]} more report{"s" if al["more"] != 1 else ""} about {e(al["target"])}</div>'
                    if al.get("more") else "")
            step = f'<div style="font-size:13px"><strong>Next step:</strong> {e(al["next_step"])}</div>' if al.get("next_step") else ""
            out.append(
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 8px;border-collapse:collapse"><tr>'
                f'<td width="4" style="background:{bar}"></td><td style="padding:6px 10px;background:{bg}">'
                f'<div style="font-size:12px"><strong style="color:{fg}">{al["severity"].upper()}</strong> · <strong>{e(al["relation_label"])}</strong> · '
                f'{e(al["kind_label"])} · <span style="color:#5b6470">{e(al["target"])} · {e(al["when"])}</span></div>'
                f'<div>{a(al.get("url"), al["title"])}</div>{more}{step}</td></tr></table>')
        if ew["has_watchlist"] and not ew["alerts"]:
            out.append('<p style="margin:0 0 6px;color:#5b6470">No new signals for your company, suppliers or technology.</p>')
        if ew.get("more"):
            out.append(f'<p style="margin:0;color:#5b6470;font-size:13px">+ {ew["more"]} lower-priority signal(s) not shown.</p>')
        if ew["actors"]:
            out.append('<p style="margin:8px 0 4px"><strong>Groups targeting your industry, active in current reporting</strong></p><ul style="margin:0;padding-left:20px">'
                       + "".join(f'<li>{a(g["url"], g["name"])} ({e(g["id"])}) — {e(", ".join(g["industries"]))}</li>' for g in ew["actors"]) + "</ul>")
        return "".join(out)
    if key == "actions" and n.get("actions"):
        return h2("Immediate actions") + '<ol style="margin:0;padding-left:20px">' + "".join(
            f'<li style="margin-bottom:4px">{e(x)}</li>' for x in n["actions"]) + "</ol>"
    if key == "themes" and n.get("themes"):
        return h2("Top themes") + '<ul style="margin:0;padding-left:20px">' + "".join(
            f'<li style="margin-bottom:4px"><strong>{e(t.get("theme", ""))}</strong>{" — " + e(t["why_it_matters"]) if t.get("why_it_matters") else ""}</li>'
            for t in n["themes"]) + "</ul>"
    if key == "attacks" and n.get("attacks"):
        return h2("Active attacks in the wild") + '<ul style="margin:0;padding-left:20px">' + "".join(
            f'<li style="margin-bottom:4px">{a(x.get("link"), x.get("title", ""))} <span style="color:#5b6470">· {e(x.get("actor") or "Unknown")}</span>'
            f'{"<br>" + e(x["why_it_matters"]) if x.get("why_it_matters") else ""}</li>' for x in n["attacks"]) + "</ul>"
    if key == "kev" and brief["kev"]:
        return h2("New CISA KEV entries") + '<ul style="margin:0;padding-left:20px">' + "".join(
            f'<li>{a(i["url"], i["title"])}</li>' for i in brief["kev"]) + "</ul>"
    if key == "vendors" and brief["vendors"]:
        rows = "".join(
            f'<tr><td valign="top" style="border-bottom:1px solid #e3e6ea;width:160px"><strong>{e(v["vendor"])}</strong></td>'
            f'<td style="border-bottom:1px solid #e3e6ea">'
            + ("".join(f'<div>{a(i["url"], i["title"])}{exploited_tag(i.get("exploited"))}</div>' for i in v["items"])
               or '<span style="color:#5b6470">Nothing new</span>') + "</td></tr>" for v in brief["vendors"])
        return h2("Your technology watchlist") + f'<table role="presentation" width="100%" cellpadding="4" cellspacing="0" style="border-collapse:collapse">{rows}</table>'
    if key == "items" and brief["items"]:
        rows = "".join(
            f'<tr><td valign="top" style="border-bottom:1px solid #e3e6ea;width:36px;color:#5b6470">{i["risk"]}</td>'
            f'<td style="border-bottom:1px solid #e3e6ea">{a(i["url"], i["title"])}'
            f'{exploited_tag(i.get("exploited"))}{epss_tag(i.get("epss"))}{matches_tag(i.get("matched"))}</td></tr>'
            for i in brief["items"])
        return h2("Top items by risk") + f'<table role="presentation" width="100%" cellpadding="4" cellspacing="0" style="border-collapse:collapse">{rows}</table>'
    return ""


def limitations(brief, n):
    out = []
    skipped = [s for s in brief["sources"] if s["status"] == "skipped" and "turned off" not in s["detail"]]
    failed = [s for s in brief["sources"] if s["status"] == "failed"]
    if failed:
        out.append("Not checked this time (unreachable): " + ", ".join(s["name"] for s in failed) + ".")
    if skipped:
        out.append("Not checked (not configured): " + ", ".join(s["name"] for s in skipped) + ".")
    if not n:
        out.append("Written sections are off; key risks are ranked by fixed rules.")
    out += n.get("limitations", []) if n else []
    return out


def render_html(brief, n, logo_mode):
    st = brief["stats"]
    stats = f'{st["included"]} relevant of {st["analyzed"]} new items reviewed'
    if st["shown"] and st["high"] and "items" in brief["sections"]:
        stats += f' · {st["high"]} rated high-risk (70+ on a 0–100 scale, listed below)'
    src = logo_src(logo_mode)
    logo = (f'<tr><td style="background:#080c15;padding:14px 20px;border-radius:8px 8px 0 0"><img src="{src}" width="220" alt="CISO Brief" '
            f'style="display:block;width:220px;max-width:100%;height:auto;border:0"></td></tr>') if src else ""
    head = n.get("headline") or brief["condition"]["name"].title() + " threat condition"
    body = "".join(section_html(k, brief, n) for k in brief["sections"])
    lim = limitations(brief, n)
    lim_html = (f'<p style="margin:18px 0 0;padding:8px 10px;background:#f6f7f9;border-radius:6px;color:#5b6470;font-size:12px">'
                + "<br>".join(e(x) for x in lim) + "</p>") if lim else ""
    p = brief["profile"]
    credits = brief.get("credits") or []
    mitre = " MITRE ATT&CK® © The MITRE Corporation." if any("MITRE" in c for c in credits) else ""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(subject(brief, n))}</title></head>
<body style="margin:0;background:#f6f7f9;font-family:{FONT};color:#1b1f24;font-size:15px;line-height:1.5">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:16px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid #e3e6ea;border-radius:8px">
{logo}
<tr><td style="padding:20px">
  <p style="margin:0;color:#5b6470;font-size:13px">{e(p['company'])} · {e(p['brief_name'])} · {e(brief['date'])}</p>
  {('<div style="margin-top:10px">' + condition_html(brief, n) + '</div>') if 'summary' in brief['sections'] else ''}
  <h1 style="margin:6px 0 6px;font-size:22px">{e(head)}</h1>
  <p style="margin:0 0 16px;color:#5b6470;font-size:13px">{stats}</p>
  {body}
  {lim_html}
</td></tr></table>
<p style="color:#5b6470;font-size:12px;max-width:640px">CISO Brief · {"AI-assisted summary; verify before acting. " if n else ""}Leak-site posts are criminals' claims until confirmed.{('<br>Sources: ' + e(' · '.join(credits)) + '.' + mitre) if credits else ''}</p>
</td></tr></table>
</body></html>"""


def render_md(brief, n):
    c, ew, p = brief["condition"], brief["early_warning"], brief["profile"]
    L = [f"# {subject(brief, n)}", "", f"*{p['company']} · {p['brief_name']} · {brief['date']}*", ""]
    if "summary" in brief["sections"]:
        L += [f"## Threat condition: **{c['name']}** ({c['level']}/5) — {c['posture']}", ""]
        if n.get("condition_rationale"):
            L += [n["condition_rationale"], ""]
        if c["drivers"]:
            L += ["Why: " + " · ".join(c["drivers"]), ""]
        risks = n.get("key_risks") or brief["key_risks_fallback"]
        if risks:
            L += ["**Today's key risks**", ""] + [
                f"{i}. {'[' + r['risk'] + '](' + r['link'] + ')' if r.get('link') else r['risk']}" + (f" — {r['why']}" if r.get("why") else "")
                for i, r in enumerate(risks[:3], 1)] + [""]
        if n.get("summary"):
            L += [n["summary"], ""]
    for key in brief["sections"]:
        if key == "early_warning" and (ew["alerts"] or ew["actors"]):
            L += ["## Early warning", ""]
            for al in ew["alerts"]:
                L.append(f"- **{al['severity'].upper()}** · {al['relation_label']} · {al['kind_label']} · {al['target']} · {al['when']}: "
                         f"[{al['title']}]({al['url']})" + (f" (+{al['more']} more)" if al.get("more") else "")
                         + (f"\n  - Next step: {al['next_step']}" if al.get("next_step") else ""))
            for g in ew["actors"]:
                L.append(f"- Active group targeting your industry: [{g['name']}]({g['url']}) ({g['id']})")
            L.append("")
        elif key == "actions" and n.get("actions"):
            L += ["## Immediate actions", ""] + [f"{i}. {x}" for i, x in enumerate(n["actions"], 1)] + [""]
        elif key == "themes" and n.get("themes"):
            L += ["## Top themes", ""] + [f"- **{t.get('theme', '')}**" + (f" — {t['why_it_matters']}" if t.get("why_it_matters") else "") for t in n["themes"]] + [""]
        elif key == "attacks" and n.get("attacks"):
            L += ["## Active attacks in the wild", ""] + [f"- [{x.get('title', '')}]({x.get('link', '')}) · {x.get('actor') or 'Unknown'}"
                                                          + (f" — {x['why_it_matters']}" if x.get("why_it_matters") else "") for x in n["attacks"]] + [""]
        elif key == "kev" and brief["kev"]:
            L += ["## New CISA KEV entries", ""] + [f"- [{i['title']}]({i['url']})" for i in brief["kev"]] + [""]
        elif key == "items" and brief["items"]:
            L += ["## Top items by risk", ""] + [f"- {i['risk']} · [{i['title']}]({i['url']})" + (" · exploited" if i.get("exploited") else "")
                                                 + (f" · matches {', '.join(i['matched'])}" if i.get("matched") else "") for i in brief["items"]] + [""]
    lim = limitations(brief, n)
    if lim:
        L += ["---", ""] + [f"*{x}*" for x in lim]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--brief", required=True)
    ap.add_argument("--narrative", default="")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--logo", default="data", choices=["data", "cid", "url", "none"],
                    help="data = embedded (files/preview), cid = for SMTP sending, url = hosted image (email connectors)")
    args = ap.parse_args()
    with open(args.brief, encoding="utf-8") as f:
        brief = json.load(f)
    n = {}
    if args.narrative and os.path.exists(args.narrative):
        with open(args.narrative, encoding="utf-8") as f:
            n = json.load(f)
    os.makedirs(args.out_dir, exist_ok=True)
    html_path = os.path.join(args.out_dir, "brief.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(brief, n, args.logo))
    with open(os.path.join(args.out_dir, "brief.md"), "w", encoding="utf-8") as f:
        f.write(render_md(brief, n))
    subj = subject(brief, n)
    with open(os.path.join(args.out_dir, "subject.txt"), "w", encoding="utf-8") as f:
        f.write(subj)
    print(f"Subject: {subj}\nWrote {html_path}, brief.md, subject.txt")


if __name__ == "__main__":
    main()
