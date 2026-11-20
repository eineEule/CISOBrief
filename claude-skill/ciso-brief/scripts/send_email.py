#!/usr/bin/env python3
"""
Optional: email the rendered brief over SMTP (Gmail App Password, Microsoft 365, any relay).
Only used when config.ini has  [delivery] mode = email  and  email_method = smtp.

    python send_email.py --config ../config.ini --html brief.html --text brief.md --subject-file subject.txt [--to a@x.com,b@y.com] [--dry-run]

Render the HTML with  render.py --logo cid  so the logo travels inside the email.
The password comes from CISO_BRIEF_SMTP_PASSWORD if set, otherwise [smtp] password. Standard library only.
"""
import argparse
import configparser
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage

LOGO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "logo-email.png")


def yes(v):
    return str(v or "").strip().lower() in ("1", "yes", "true", "on", "y")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--html", required=True)
    ap.add_argument("--text", default="")
    ap.add_argument("--subject-file", default="")
    ap.add_argument("--to", default="", help="Overrides [delivery] recipients")
    ap.add_argument("--dry-run", action="store_true", help="Build the message and print who it would go to; send nothing")
    args = ap.parse_args()

    cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    cfg.read(args.config, encoding="utf-8")
    s = cfg["smtp"] if cfg.has_section("smtp") else {}
    host = (s.get("host") or "").strip()
    port = int(s.get("port") or 587)
    user = (s.get("username") or "").strip()
    password = os.environ.get("CISO_BRIEF_SMTP_PASSWORD") or (s.get("password") or "")
    password = password.replace(" ", "").strip()  # Gmail shows app passwords in groups of four
    sender = (s.get("from") or user).strip()
    to = [x.strip() for x in (args.to or cfg.get("delivery", "recipients", fallback="") or user).split(",") if x.strip()]
    missing = [k for k, v in (("[smtp] host", host), ("[smtp] from or username", sender), ("recipients", to)) if not v]
    if missing:
        sys.exit("Email not sent: missing " + ", ".join(missing) + " in config.ini.")

    with open(args.html, encoding="utf-8") as f:
        html = f.read()
    text = "View this brief in an email app that shows HTML."
    if args.text and os.path.exists(args.text):
        with open(args.text, encoding="utf-8") as f:
            text = f.read()
    subject = "CISO Brief"
    if args.subject_file and os.path.exists(args.subject_file):
        with open(args.subject_file, encoding="utf-8") as f:
            subject = f.read().strip() or subject

    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, ", ".join(to)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    if "cid:cisobrief-logo" in html and os.path.exists(LOGO_FILE):
        with open(LOGO_FILE, "rb") as f:
            msg.get_payload()[1].add_related(f.read(), maintype="image", subtype="png", cid="<cisobrief-logo>",
                                             filename="cisobrief-logo.png", disposition="inline")

    if args.dry_run:
        print(f"Dry run: would send '{subject}' from {sender} to {', '.join(to)} via {host}:{port} ({len(msg.as_bytes()):,} bytes).")
        return
    use_ssl, use_tls = yes(s.get("use_ssl")), yes(s.get("use_tls", "yes"))
    ctx = ssl.create_default_context()
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=30)
            if use_tls:
                server.starttls(context=ctx)
        with server:
            if user and password:
                server.login(user, password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        sys.exit("Email not sent: the SMTP server rejected the username/password. For Gmail, use an App Password "
                 "(https://myaccount.google.com/apppasswords), not your normal password.")
    except (OSError, smtplib.SMTPException) as e:
        sys.exit(f"Email not sent: {type(e).__name__}: {e}")
    print(f"Sent '{subject}' to {', '.join(to)}.")


if __name__ == "__main__":
    main()
