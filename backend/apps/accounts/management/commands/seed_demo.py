"""
Seed a demo customer so the product shows real value before real customers exist.

The company itself is fictional (its .example domain is reserved and never resolves),
but everything around it is real: its industry, the technology it runs and its
suppliers are real, so KEV/news, likely-exploited CVEs, ATT&CK groups and supplier
early-warning checks all return live data.
"""
from django.core.management.base import BaseCommand

from apps.accounts.models import Organization, User
from apps.accounts.services import create_organization_for

DEMO = {
    "name": "Ridgeline Builders Group",
    "domain": "ridgelinebuilders.example",
    "industry": "Construction",
}
PROFILE = {
    "industries": ["Construction", "Manufacturing / Industrial"],
    "vendors": ["Microsoft", "Fortinet", "Cisco", "Okta", "VMware / Broadcom", "Procore", "Autodesk", "Trimble", "ConnectWise"],
    "keywords": ["building automation", "BIM", "SCADA", "payroll"],
    "threat_actors": ["Akira", "Play", "Black Basta"],
    "watch_names": ["Ridgeline Builders Group", "Ridgeline Builders"],
    "watch_domains": ["ridgelinebuilders.example"],
    "suppliers": [
        {"name": "Procore Technologies", "domain": "procore.com"},
        {"name": "Autodesk", "domain": "autodesk.com"},
        {"name": "Trimble", "domain": "trimble.com"},
        {"name": "ConnectWise", "domain": "connectwise.com"},
    ],
}


class Command(BaseCommand):
    help = "Create (or refresh) the demo company 'Ridgeline Builders Group' with a Board brief and a SOC digest."

    def add_arguments(self, parser):
        parser.add_argument("--email", action="append", help="Add this user to the demo company as owner (repeatable). "
                                                             "Default: every user who has no organization yet.")
        parser.add_argument("--now", action="store_true",
                            help="Collect feeds, scan the watchlists and build both briefs right away (takes a few minutes).")

    def handle(self, *args, **opts):
        org = Organization.objects.filter(name=DEMO["name"]).first()
        users = list(User.objects.filter(email__in=opts["email"])) if opts["email"] else list(User.objects.filter(organization__isnull=True))
        if opts["email"] and len(users) != len(set(opts["email"])):
            self.stdout.write(self.style.WARNING("Some --email addresses don't match an existing user; they were skipped."))

        if org is None:
            if not users:
                anchor = User.objects.filter(is_superuser=True).first()
                if anchor is None:
                    self.stderr.write("Create a user first: python manage.py createsuperuser")
                    return
                users = [anchor]
            org = create_organization_for(users[0], DEMO["name"], DEMO["domain"], DEMO["industry"], plan="professional")
            self.stdout.write(self.style.SUCCESS(f"Created demo organization {org.name}"))
        for u in users:
            u.organization, u.role = org, "owner"
            u.save(update_fields=["organization", "role"])
            self.stdout.write(f"  {u.email} → owner of {org.name}")

        soc = org.mailers.filter(name__in=["Daily Threat Brief", "Daily SOC Digest"]).first() or org.mailers.create(name="Daily SOC Digest")
        for k, v in PROFILE.items():
            setattr(soc, k, v)
        soc.name, soc.audience, soc.frequency, soc.send_hour, soc.timezone = "Daily SOC Digest", "technical", "daily", 6, "America/New_York"
        soc.sections = ["early_warning", "actions", "attacks", "kev", "vendors", "items"]
        soc.min_risk, soc.max_items, soc.exploited_only, soc.send_to_all_members, soc.is_active = 50, 12, False, True, True
        soc.save()

        board, _ = org.mailers.get_or_create(name="Monday Board Brief")
        for k, v in PROFILE.items():
            setattr(board, k, v)
        board.audience, board.frequency, board.send_weekday, board.send_hour, board.timezone = "executive", "weekly", 0, 7, "America/New_York"
        board.sections = ["summary", "early_warning", "actions", "themes", "vendors"]
        board.min_risk, board.max_items, board.exploited_only, board.send_to_all_members, board.is_active = 70, 8, False, True, True
        board.save()
        self.stdout.write(self.style.SUCCESS(f"Mailers ready: {soc.name} ({soc.schedule_display()}), {board.name} ({board.schedule_display()})"))

        if not opts["now"]:
            from apps.watch.tasks import scan_mailer

            scan_mailer.delay(str(soc.id))
            self.stdout.write("Queued an early-warning scan. Re-run with --now to also build the briefs immediately.")
            return

        from apps.intelligence.tasks import fetch_kev_daily, fetch_rss_feeds
        from apps.reports.utils import BriefBuilder
        from apps.watch import collectors
        from apps.watch.targets import targets_for

        self.stdout.write("Collecting CISA KEV + news feeds…")
        self.stdout.write(f"  KEV: {fetch_kev_daily()} new · RSS: {fetch_rss_feeds()} new")
        self.stdout.write("Loading MITRE ATT&CK groups…")
        self.stdout.write(f"  {collectors.refresh_attack_groups()} groups")
        t = targets_for([soc])
        for label, fn in [("RansomLook leak sites", lambda: collectors.collect_ransomlook(t, days=30)),
                          ("Hudson Rock infostealers", lambda: collectors.collect_hudsonrock(t)),
                          ("AlienVault OTX", lambda: collectors.collect_otx(t)),
                          ("abuse.ch URLhaus", lambda: collectors.collect_urlhaus(t)),
                          ("NVD + EPSS likely exploits", lambda: collectors.collect_likely_exploits(t)),
                          ("EPSS enrichment", collectors.enrich_threat_items_epss)]:
            self.stdout.write(f"Scanning {label}…")
            self.stdout.write(f"  {fn()} new")
        for mailer in (soc, board):
            report = BriefBuilder(mailer).generate(force=True)
            self.stdout.write(self.style.SUCCESS(f"{mailer.name}: {report.status} — {report.headline}"))
        self.stdout.write("Open http://localhost to read them. Use 'Send now' on the Mailers page to email one to Mailpit.")
