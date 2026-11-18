from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from .forms import OnboardingForm
from .services import create_organization_for


@login_required
def onboarding(request):
    if request.user.organization_id:
        return redirect("/")
    form = OnboardingForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        org = create_organization_for(request.user, form.cleaned_data["organization_name"],
                                      form.cleaned_data.get("company_domain", ""), form.cleaned_data.get("industry", ""))
        messages.success(request, f"Welcome to CISO Brief, {org.name}. We set up a Daily Threat Brief — tailor it below.")
        mailer = org.mailers.first()
        return redirect(f"/mailers/{mailer.id}/" if mailer else "/mailers/")
    return render(request, "accounts/onboarding.html", {"form": form})
