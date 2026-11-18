import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.mailers.models import Mailer
from apps.reports import ai
from apps.reports.utils import BriefBuilder


class Command(BaseCommand):
    help = "Check the AI provider in .env works, then show how Executive vs Technical tone changes the same brief."

    def add_arguments(self, parser):
        parser.add_argument("--mailer", help="Mailer UUID for the tone comparison (default: first active mailer)")
        parser.add_argument("--quick", action="store_true", help="Only check the connection (one tiny call)")

    def handle(self, *args, **opts):
        if not ai.enabled():
            raise CommandError("AI is off: AI_BASE_URL and AI_API_KEY are both empty in .env. "
                               "Free options: local Ollama (docker compose --profile local-ai up -d) or a Google Gemini key.")
        self.stdout.write(f"Provider: {ai.provider_label()}  ·  model: {settings.AI_MODEL}  ·  timeout: {settings.AI_TIMEOUT}s")
        t = time.monotonic()
        data, err = ai.chat_json("Reply only with JSON.", 'Reply with exactly {"ok": true}', temperature=0)
        if err:
            raise CommandError(f"AI call failed: {err}")
        self.stdout.write(self.style.SUCCESS(f"1/2 Connection and model work ({time.monotonic() - t:.1f}s): {data}"))
        if opts["quick"]:
            return

        mailer = Mailer.objects.filter(id=opts["mailer"]).first() if opts["mailer"] else Mailer.objects.filter(is_active=True).first()
        if not mailer:
            self.stdout.write("No mailer to compare tones with; skipping step 2.")
            return
        self.stdout.write(f"2/2 Same data, both audiences, using '{mailer.name}' (2 AI calls)...")
        for audience in ("executive", "technical"):
            mailer.audience = audience  # in memory only, never saved
            t = time.monotonic()
            b = BriefBuilder(mailer).compose(use_ai=True, include_processed=True)
            self.stdout.write(self.style.HTTP_INFO(f"\n=== {audience.upper()} (ai: {b.get('ai_status')}, {time.monotonic() - t:.0f}s) ==="))
            self.stdout.write(f"Headline: {b['headline']}")
            if b.get("summary"):
                self.stdout.write(f"Summary:  {b['summary']}")
            for a in b.get("actions", [])[:3]:
                self.stdout.write(f"  - {a}")
            if b.get("ai_status") == "failed":
                self.stdout.write(self.style.ERROR(f"AI failed: {b.get('ai_error')}"))
            if b.get("ai_status") == "no_data":
                self.stdout.write("Nothing in the last 30 days matched this mailer, so there was nothing to summarize.")
