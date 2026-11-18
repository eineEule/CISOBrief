"""Creating an organization and making a user its owner (used by sign-up, onboarding and the demo seed)."""
from django.db import transaction
from django.utils.text import slugify

from .models import Organization


def unique_slug(name: str) -> str:
    base = slugify(name)[:40] or "org"
    slug, n = base, 2
    while Organization.objects.filter(slug=slug).exists():
        slug, n = f"{base}-{n}", n + 1
    return slug


@transaction.atomic
def create_organization_for(user, name: str, domain: str = "", industry: str = "", plan: str = "free") -> Organization:
    """Create the org, make `user` its owner, and seed its default mailer's watchlist."""
    from apps.watch.targets import is_domain, normalize_domain

    org = Organization.objects.create(name=name.strip(), slug=unique_slug(name), plan=plan,
                                      focus_industries=[industry] if industry else [])
    user.organization = org
    user.role = "owner"
    user.save(update_fields=["organization", "role"])

    mailer = org.mailers.first()  # created by the post_save signal
    if mailer:
        domain = normalize_domain(domain)
        mailer.watch_names = [org.name] if len(org.name) >= 4 else []
        mailer.watch_domains = [domain] if domain and is_domain(domain) else []
        if industry:
            mailer.industries = [industry]
        mailer.save()
    return org
