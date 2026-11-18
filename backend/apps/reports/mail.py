"""SMTP helpers: what we're sending through, and errors a person can act on."""
import smtplib
import socket
import ssl

from django.conf import settings


def is_dev_inbox() -> bool:
    return settings.EMAIL_HOST in ("mailpit", "localhost", "127.0.0.1") and not settings.EMAIL_HOST_USER


def describe() -> str:
    if is_dev_inbox():
        return "Mailpit dev inbox (http://localhost:8025) — nothing leaves this machine"
    mode = "SSL" if settings.EMAIL_USE_SSL else ("STARTTLS" if settings.EMAIL_USE_TLS else "no encryption")
    return f"{settings.EMAIL_HOST}:{settings.EMAIL_PORT} ({mode}) as {settings.EMAIL_HOST_USER or 'no login'}"


def friendly_error(e) -> str:
    host = f"{settings.EMAIL_HOST}:{settings.EMAIL_PORT}"
    if isinstance(e, smtplib.SMTPAuthenticationError):
        msg = f"{host} rejected the username/password"
        if "gmail" in settings.EMAIL_HOST:
            msg += " — Gmail needs an App Password (Google Account → Security → 2-Step Verification → App passwords), not your normal password"
        return msg
    if isinstance(e, smtplib.SMTPSenderRefused):
        return f"{host} won't send as {settings.DEFAULT_FROM_EMAIL} — set DEFAULT_FROM_EMAIL to the account's own address or a verified sender"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return f"{host} refused the recipient address"
    if isinstance(e, smtplib.SMTPNotSupportedError) or "STARTTLS" in str(e):
        return f"{host} doesn't support STARTTLS here — try EMAIL_PORT=465 with EMAIL_USE_SSL=1 and EMAIL_USE_TLS=0"
    if isinstance(e, (ssl.SSLError,)) or "WRONG_VERSION_NUMBER" in str(e):
        return f"TLS mismatch talking to {host} — port 587 uses EMAIL_USE_TLS=1, port 465 uses EMAIL_USE_SSL=1"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return f"timed out reaching {host} — check EMAIL_HOST/EMAIL_PORT (some networks/ISPs block outbound SMTP)"
    if isinstance(e, (socket.gaierror,)):
        return f"can't resolve {settings.EMAIL_HOST} — check EMAIL_HOST"
    if isinstance(e, (ConnectionRefusedError, OSError)):
        return f"couldn't connect to {host} — check EMAIL_HOST/EMAIL_PORT"
    return f"{type(e).__name__}: {e}"
