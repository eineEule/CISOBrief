from django import forms

from apps.accounts.models import Organization, User

from apps.watch.targets import is_domain, normalize_domain

from . import catalog
from .models import Mailer


def _split(value: str):
    seen, out = set(), []
    for part in (value or "").replace("\n", ",").split(","):
        p = part.strip()
        if p and p.lower() not in seen:
            seen.add(p.lower())
            out.append(p[:80])
    return out[:50]


class MailerForm(forms.ModelForm):
    organization = forms.ModelChoiceField(queryset=Organization.objects.filter(is_active=True), required=False)
    industries = forms.MultipleChoiceField(choices=catalog.INDUSTRY_CHOICES, required=False, widget=forms.CheckboxSelectMultiple)
    vendors = forms.MultipleChoiceField(choices=catalog.VENDOR_CHOICES, required=False, widget=forms.CheckboxSelectMultiple)
    other_vendors = forms.CharField(required=False, widget=forms.TextInput(attrs={"placeholder": "e.g. Sage 300 CRE, Viewpoint Vista, HCSS HeavyJob"}),
                                    help_text="Products not in the list. Use the full product name as it appears in advisories — very short or generic names match noise.")
    keywords = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2, "placeholder": "e.g. SCADA, Procore, Autodesk, BIM"}),
                               help_text="Comma-separated. Whole-word match.")
    threat_actors = forms.CharField(required=False, widget=forms.TextInput(attrs={"placeholder": "e.g. Volt Typhoon, Scattered Spider"}),
                                    help_text="Comma-separated.")
    watch_names = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2, "placeholder": "Acme Construction Inc, Acme Builders"}),
                                  help_text="Comma-separated. Use full names (4+ letters) as they'd appear in a headline or leak-site post.")
    watch_domains = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2, "placeholder": "acmeconstruction.com, acme-builders.com"}),
                                    help_text="Comma-separated. Used for lookalike-domain, infostealer, malware-hosting and leak-site checks.")
    suppliers = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Procore Technologies, procore.com\nSmith Electrical Contractors, smithelectric.com"}),
                                help_text="One per line: Name, domain. Either part can be blank. Up to 50.")
    sections = forms.CharField(widget=forms.HiddenInput, required=False)
    sources = forms.MultipleChoiceField(choices=catalog.SOURCES, required=False, widget=forms.CheckboxSelectMultiple,
                                        initial=catalog.SOURCE_KEYS)
    min_risk = forms.IntegerField(min_value=0, max_value=95, initial=50,
                                  widget=forms.NumberInput(attrs={"type": "range", "step": 5}))
    max_items = forms.IntegerField(min_value=3, max_value=25, initial=10)
    recipients = forms.ModelMultipleChoiceField(queryset=User.objects.none(), required=False, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = Mailer
        fields = [
            "organization", "name", "is_active", "audience",
            "industries", "vendors", "keywords", "threat_actors",
            "watch_names", "watch_domains", "suppliers",
            "sections", "min_risk", "exploited_only", "sources", "max_items",
            "frequency", "send_weekday", "send_hour", "timezone", "send_to_all_members", "recipients",
        ]
        widgets = {"audience": forms.RadioSelect}

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        inst = self.instance
        org = inst.organization if inst.organization_id else (user.organization if user else None)
        # Only staff without an org pick the organization explicitly.
        if org is not None or not (user and user.is_staff):
            del self.fields["organization"]
        else:
            self.fields["organization"].required = True
        self.org = org
        if org is not None:
            self.fields["recipients"].queryset = org.users.filter(is_active=True).order_by("email")
        if not self.is_bound:
            self.initial["vendors"] = [v for v in inst.vendors or [] if v in catalog.VENDORS]
            self.initial["other_vendors"] = ", ".join(v for v in inst.vendors or [] if v not in catalog.VENDORS)
            self.initial["keywords"] = ", ".join(inst.keywords or [])
            self.initial["threat_actors"] = ", ".join(inst.threat_actors or [])
            self.initial["watch_names"] = ", ".join(inst.watch_names or [])
            self.initial["watch_domains"] = ", ".join(inst.watch_domains or [])
            self.initial["suppliers"] = "\n".join(", ".join(p for p in (x.get("name", ""), x.get("domain", "")) if p) for x in inst.suppliers or [])
            self.initial["sections"] = ",".join(inst.sections or catalog.DEFAULT_SECTIONS)
            if not inst.pk:
                self.initial["sources"] = list(catalog.SOURCE_KEYS)

    def clean_keywords(self):
        return _split(self.cleaned_data.get("keywords"))

    def clean_threat_actors(self):
        return _split(self.cleaned_data.get("threat_actors"))

    def clean_other_vendors(self):
        others = _split(self.cleaned_data.get("other_vendors"))
        known = {v.lower(): v for v in catalog.VENDORS}
        short = [o for o in others if len(o) < 3]
        if short:
            raise forms.ValidationError(f"Too short to match reliably: {', '.join(short)}")
        if len(others) > 30:
            raise forms.ValidationError("Up to 30 other products.")
        # Someone typing a listed vendor into Other gets the listed one (with its full set of match terms).
        return [known.get(o.lower(), o[:60]) for o in others]

    def clean_watch_names(self):
        names = _split(self.cleaned_data.get("watch_names"))
        short = [n for n in names if len(n) < 4]
        if short:
            raise forms.ValidationError(f"Too short to match reliably: {', '.join(short)}")
        return names

    def clean_watch_domains(self):
        domains = [normalize_domain(d) for d in _split(self.cleaned_data.get("watch_domains"))]
        bad = [d for d in domains if not is_domain(d)]
        if bad:
            raise forms.ValidationError(f"Not a valid domain: {', '.join(bad)}")
        return list(dict.fromkeys(domains))[:20]

    def clean_suppliers(self):
        out, errors = [], []
        for line in (self.cleaned_data.get("suppliers") or "").splitlines():
            parts = [p.strip() for p in line.replace("|", ",").split(",") if p.strip()]
            if not parts:
                continue
            domain = next((normalize_domain(p) for p in parts if is_domain(p)), "")
            name = ", ".join(p for p in parts if normalize_domain(p) != domain)
            if not domain and len(name) < 4:
                errors.append(line.strip())
                continue
            out.append({"name": name[:120], "domain": domain})
        if errors:
            raise forms.ValidationError(f"Couldn't read: {'; '.join(errors[:5])}. Use “Name, domain.com”.")
        return out[:50]

    def clean_sections(self):
        keys = [k.strip() for k in (self.cleaned_data.get("sections") or "").split(",") if k.strip()]
        keys = [k for i, k in enumerate(keys) if k in catalog.SECTION_LABELS and k not in keys[:i]]
        if not keys:
            raise forms.ValidationError("Turn on at least one section.")
        return keys

    def clean_sources(self):
        sources = self.cleaned_data.get("sources") or []
        if not sources:
            raise forms.ValidationError("Pick at least one source.")
        return list(sources)

    def clean(self):
        data = super().clean()
        merged = list(data.get("vendors") or [])
        for o in data.get("other_vendors") or []:
            if o.lower() not in {m.lower() for m in merged}:
                merged.append(o)
        data["vendors"] = merged
        if not data.get("send_to_all_members") and not data.get("recipients") and self.org is not None:
            self.add_error("recipients", "Pick at least one recipient, or send to all members.")
        return data

    def save(self, commit=True):
        mailer = super().save(commit=False)
        if not mailer.organization_id:
            mailer.organization = self.org or self.cleaned_data.get("organization")
        if commit:
            mailer.save()
            self.save_m2m()
        return mailer
