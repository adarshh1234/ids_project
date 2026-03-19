from django.contrib import admin
from .models import Alert, NetworkSample

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'timestamp', 'attack_category', 'severity', 'confidence', 'status', 'source_ip']
    list_filter = ['severity', 'attack_category', 'status']
    search_fields = ['source_ip', 'destination_ip', 'attack_category']
    readonly_fields = ['blockchain_block_index', 'blockchain_hash']

@admin.register(NetworkSample)
class NetworkSampleAdmin(admin.ModelAdmin):
    list_display = ['id', 'timestamp']
