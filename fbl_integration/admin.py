from django.contrib import admin
from .models import FblAccount

@admin.register(FblAccount)
class FblAccountAdmin(admin.ModelAdmin):
    list_display = ["system_username", "username", "badge_number", "status", "tags_secured", "created_at"]
    search_fields = ["badge_number", "username"]
    list_filter = ["status"]
    readonly_fields = ["badge_number", "account_id", "username", "status", "tags_secured", "created_at"]

    def system_username(self, x):
        return x.user.username
    system_username.short_description = 'System Username'
