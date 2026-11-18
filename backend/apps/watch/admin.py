from django.contrib import admin

from .models import AttackGroup, DomainExposure, WatchSignal


@admin.register(WatchSignal)
class WatchSignalAdmin(admin.ModelAdmin):
    list_display = ["discovered_at", "kind", "target", "title", "source"]
    list_filter = ["kind", "source", "target_type"]
    search_fields = ["target", "title", "detail"]
    readonly_fields = ["fingerprint", "data", "discovered_at"]


@admin.register(DomainExposure)
class DomainExposureAdmin(admin.ModelAdmin):
    list_display = ["domain", "employees", "users", "third_parties", "last_employee_compromised", "checked_at"]
    search_fields = ["domain"]


@admin.register(AttackGroup)
class AttackGroupAdmin(admin.ModelAdmin):
    list_display = ["attack_id", "name", "modified"]
    search_fields = ["name", "attack_id", "description"]
