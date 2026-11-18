from django.contrib import admin

from .models import CustomKeyword, ProcessedItem, ThreatActor, ThreatItem


@admin.register(ThreatItem)
class ThreatItemAdmin(admin.ModelAdmin):
    list_display = ["title", "source", "cve_id", "risk_score", "is_actively_exploited", "published_at"]
    list_filter = ["source", "is_actively_exploited", "is_zero_day", "is_ransomware"]
    search_fields = ["title", "cve_id", "threat_actor"]
    date_hierarchy = "published_at"
    readonly_fields = ["content_hash", "raw_data", "discovered_at", "updated_at"]


@admin.register(ThreatActor)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display = ["name", "actor_type", "country_origin", "is_active", "last_activity"]
    list_filter = ["actor_type", "is_active"]
    search_fields = ["name"]


@admin.register(CustomKeyword)
class CustomKeywordAdmin(admin.ModelAdmin):
    list_display = ["keyword", "organization", "weight", "is_active"]
    list_filter = ["organization", "is_active"]


@admin.register(ProcessedItem)
class ProcessedItemAdmin(admin.ModelAdmin):
    list_display = ["threat_item", "organization", "included_in_report", "processed_at"]
    list_filter = ["organization"]
