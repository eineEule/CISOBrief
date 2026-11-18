from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.template.loader import render_to_string
from django.shortcuts import get_object_or_404, render
from django.utils.safestring import mark_safe

from apps.reports.models import Report


def _reports_for(user):
    if user.is_staff:
        return Report.objects.select_related("organization", "mailer")
    if user.organization_id:
        return Report.objects.filter(organization_id=user.organization_id).select_related("organization", "mailer")
    return Report.objects.none()


@login_required
def index(request):
    reports = _reports_for(request.user)[:60]
    return render(request, "dashboard/index.html", {"reports": reports})


@login_required
def report_detail(request, report_id):
    report = get_object_or_404(_reports_for(request.user), id=report_id)
    if not report.html_content:
        raise Http404("Report has no content yet")
    # Re-render from the stored brief so older reports pick up template changes (logo, layout);
    # fall back to the HTML saved at generation time. Both come from our own autoescaped template.
    body = report.html_content
    if report.content:
        try:
            body = render_to_string("reports/report_template.html", {"brief": report.content})
        except Exception:
            pass
    return render(request, "reports/report_detail.html", {"report": report, "body": mark_safe(body)})
