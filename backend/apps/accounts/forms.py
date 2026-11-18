from django import forms

from apps.mailers import catalog
from apps.watch.targets import is_domain, normalize_domain

INDUSTRY_CHOICES = [("", "Select your industry")] + catalog.INDUSTRY_CHOICES


class OrganizationFieldsMixin(forms.Form):
    organization_name = forms.CharField(label="Company name", max_length=255,
                                        widget=forms.TextInput(attrs={"placeholder": "Acme Construction Inc"}))
    company_domain = forms.CharField(label="Company domain", required=False, max_length=255,
                                     widget=forms.TextInput(attrs={"placeholder": "acmeconstruction.com"}),
                                     help_text="Used to watch for lookalike domains, leaked credentials and leak-site posts.")
    industry = forms.ChoiceField(label="Industry", choices=INDUSTRY_CHOICES, required=False)

    def clean_organization_name(self):
        name = self.cleaned_data["organization_name"].strip()
        if len(name) < 2:
            raise forms.ValidationError("Enter your company's name.")
        return name

    def clean_company_domain(self):
        d = normalize_domain(self.cleaned_data.get("company_domain", ""))
        if d and not is_domain(d):
            raise forms.ValidationError("That doesn't look like a domain (e.g. acmeconstruction.com).")
        return d


class OrgSignupForm(OrganizationFieldsMixin):
    """allauth ACCOUNT_SIGNUP_FORM_CLASS: extra fields on the sign-up page."""

    def signup(self, request, user):
        from .services import create_organization_for

        create_organization_for(user, self.cleaned_data["organization_name"],
                                self.cleaned_data.get("company_domain", ""), self.cleaned_data.get("industry", ""))


class OnboardingForm(OrganizationFieldsMixin):
    pass
