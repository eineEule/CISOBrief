from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.safestring import mark_safe
from django.template.loader import render_to_string
from django.views.decorators.http import require_POST

from apps.reports.ai import enabled as ai_enabled, provider_label as ai_provider_label
from apps.reports.mail import describe as smtp_describe

from . import catalog
from .forms import MailerForm
from .models import Mailer


def _visible_mailers(user):
    qs = Mailer.objects.select_related("organization")
    if user.is_staff:
        return qs
    if user.organization_id:
        return qs.filter(organization_id=user.organization_id)
    return qs.none()


def can_manage(user, org=None) -> bool:
    if user.is_staff:
        return True
    if not user.organization_id or not user.is_admin:
        return False
    return org is None or org.id == user.organization_id


@login_required
def mailer_list(request):
    mailers = _visible_mailers(request.user).prefetch_related("reports")
    rows = []
    for m in mailers:
        last = m.reports.order_by("-report_date").first()
        rows.append({"m": m, "last": last, "recipients": m.recipient_users().count()})
    return render(request, "mailers/list.html", {"rows": rows, "can_manage": can_manage(request.user)})


def _queue_scan(request, mailer):
    if mailer.watch_domains or mailer.watch_names or mailer.suppliers or mailer.vendors:
        from apps.watch.tasks import scan_mailer

        scan_mailer.delay(str(mailer.id))
        messages.info(request, "Scanning the early-warning sources for this watchlist now — results show up in Preview within a few minutes.")


def _source_status():
    keyed = {"otx": bool(settings.OTX_API_KEY), "urlhaus": bool(settings.ABUSECH_AUTH_KEY), "nvd": True}
    return [
        ("RansomLook", "Leak-site posts", True), ("crt.sh", "Lookalike certs", True),
        ("Hudson Rock", "Infostealers", True), ("AlienVault OTX", "Threat reports", keyed["otx"]),
        ("abuse.ch URLhaus", "Malware hosting", keyed["urlhaus"]), ("NVD + FIRST EPSS", "Exploit prediction", True),
        ("MITRE ATT&CK", "Industry actors", True), ("CISA KEV", "Exploited CVEs", True),
    ]


def _form_context(form, mailer=None):
    sections_meta = [(k, label, *catalog.SECTION_META.get(k, ("", ""))) for k, label in catalog.SECTIONS]
    org = form.org
    return {
        "form": form, "mailer": mailer,
        "section_catalog": sections_meta,
        "ai_sections": sorted(catalog.AI_SECTIONS),
        "vendor_groups": catalog.VENDOR_GROUPS,
        "audience_cards": catalog.AUDIENCE_CARDS,
        "source_status": _source_status(),
        "member_count": org.users.filter(is_active=True, email_reports=True).count() if org else 0,
        "from_email": settings.DEFAULT_FROM_EMAIL,
        "smtp_desc": smtp_describe(),
        "has_ai_key": ai_enabled(),
        "ai_model": settings.AI_MODEL,
        "ai_provider": ai_provider_label(),
    }


@login_required
def mailer_create(request):
    if not can_manage(request.user):
        raise PermissionDenied("Only organization owners/admins can build mailers.")
    form = MailerForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        mailer = form.save()
        messages.success(request, f"Mailer “{mailer.name}” created. Next send: {mailer.schedule_display()}.")
        _queue_scan(request, mailer)
        return redirect("mailers:list")
    return render(request, "mailers/form.html", _form_context(form))


@login_required
def mailer_edit(request, mailer_id):
    mailer = get_object_or_404(_visible_mailers(request.user), id=mailer_id)
    if not can_manage(request.user, mailer.organization):
        raise PermissionDenied
    form = MailerForm(request.POST or None, instance=mailer, user=request.user)
    if request.method == "POST" and form.is_valid():
        watch_before = (mailer.watch_domains, mailer.watch_names, mailer.suppliers, mailer.vendors)
        form.save()
        messages.success(request, f"Saved “{mailer.name}”.")
        if (mailer.watch_domains, mailer.watch_names, mailer.suppliers, mailer.vendors) != watch_before:
            _queue_scan(request, mailer)
        return redirect("mailers:list")
    return render(request, "mailers/form.html", _form_context(form, mailer))


@login_required
@require_POST
def mailer_preview(request, mailer_id=None):
    """Preview the current (possibly unsaved) builder settings against recent data. Saves nothing."""
    from apps.reports.utils import BriefBuilder

    instance = None
    if mailer_id:
        instance = get_object_or_404(_visible_mailers(request.user), id=mailer_id)
    if not can_manage(request.user, instance.organization if instance else None):
        raise PermissionDenied
    form = MailerForm(request.POST, instance=instance or Mailer(), user=request.user)
    as_json = request.POST.get("format") == "json"
    if not form.is_valid():
        if as_json:
            return JsonResponse({"ok": False, "errors": {f: [str(e) for e in errs] for f, errs in form.errors.items()}})
        return render(request, "mailers/preview.html", {"errors": form.errors}, status=400)
    draft = form.save(commit=False)  # not saved: no DB writes
    use_ai = request.POST.get("preview_ai") == "1"
    brief = BriefBuilder(draft).compose(use_ai=use_ai, include_processed=True)
    if as_json:
        from apps.reports.utils import email_subject

        org = draft.organization
        if form.cleaned_data.get("send_to_all_members"):
            emails = list(org.users.filter(is_active=True, email_reports=True).values_list("email", flat=True))
        else:
            emails = [u.email for u in form.cleaned_data.get("recipients") or []]
        html = render_to_string("reports/email_template.html", {"brief": brief, "user": request.user, "view_url": "#"})
        ew = brief.get("early_warning") or {}
        return JsonResponse({
            "ok": True, "html": html, "subject": email_subject(brief, brief["headline"]),
            "from": settings.DEFAULT_FROM_EMAIL, "to": emails[:3], "to_count": len(emails),
            "generated": timezone.localtime().strftime("%H:%M:%S"), "ai": use_ai,
            "ai_status": brief.get("ai_status", ""), "ai_error": brief.get("ai_error", ""),
            "stats": brief["stats"], "critical": ew.get("critical", 0), "high": ew.get("high", 0),
        })
    body = mark_safe(render_to_string("reports/report_template.html", {"brief": brief}))
    return render(request, "mailers/preview.html", {"body": body, "draft": draft, "use_ai": use_ai})


@login_required
@require_POST
def mailer_test_send(request, mailer_id=None):
    """Email the current (possibly unsaved) preview to the signed-in user only. Saves nothing."""
    from apps.reports import mail as smtp
    from apps.reports.utils import BriefBuilder, email_subject

    instance = get_object_or_404(_visible_mailers(request.user), id=mailer_id) if mailer_id else None
    if not can_manage(request.user, instance.organization if instance else None):
        raise PermissionDenied
    form = MailerForm(request.POST, instance=instance or Mailer(), user=request.user)
    if not form.is_valid():
        return JsonResponse({"ok": False, "error": "Fix the highlighted fields first."})
    draft = form.save(commit=False)
    brief = BriefBuilder(draft).compose(use_ai=request.POST.get("preview_ai") == "1", include_processed=True)
    from apps.reports.utils import LOGO_CID, attach_logo

    html = render_to_string("reports/email_template.html", {"brief": brief, "user": request.user, "view_url": settings.SITE_URL,
                                                             "logo_src": f"cid:{LOGO_CID}"})
    from django.core.mail import EmailMultiAlternatives

    msg = EmailMultiAlternatives(subject="[TEST] " + email_subject(brief, brief["headline"]),
                                 body=f"Test of “{draft.name}”. View the HTML version of this email.",
                                 from_email=settings.DEFAULT_FROM_EMAIL, to=[request.user.email])
    msg.attach_alternative(html, "text/html")
    attach_logo(msg)
    try:
        msg.send()
    except Exception as e:
        return JsonResponse({"ok": False, "error": smtp.friendly_error(e)})
    return JsonResponse({"ok": True, "to": request.user.email, "via": smtp.describe(), "dev": smtp.is_dev_inbox()})


@login_required
@require_POST
def mailer_send_now(request, mailer_id):
    from .tasks import generate_mailer_report

    mailer = get_object_or_404(_visible_mailers(request.user), id=mailer_id)
    if not can_manage(request.user, mailer.organization):
        raise PermissionDenied
    generate_mailer_report.delay(str(mailer.id), force=True)
    messages.success(request, f"Building “{mailer.name}” now. It'll land in recipients' inboxes in a minute or two.")
    return redirect("mailers:list")
