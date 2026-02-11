from django.contrib import admin
from django.utils.html import format_html
from .models import ScanHistory, ThreatIndicator

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'truncated_content', 'security_score', 'severity_badge', 'user', 'created_at')
    list_filter = ('scan_type', 'created_at', 'user')
    search_fields = ('content', 'result')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'
    list_per_page = 20
    
    fieldsets = (
        ('Scan Information', {
            'fields': ('user', 'scan_type', 'content', 'created_at')
        }),
        ('Scan Results', {
            'fields': ('result_preview',),
            'classes': ('collapse',)
        }),
    )
    
    def truncated_content(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    truncated_content.short_description = 'Content'
    
    def security_score(self, obj):
        if obj.result and 'score' in obj.result:
            score = obj.result['score']
            color = 'green' if score >= 80 else 'orange' if score >= 60 else 'red'
            return format_html(
                '<span style="color: {}; font-weight: bold;">{}/100</span>',
                color, score
            )
        return 'N/A'
    security_score.short_description = 'Score'
    
    def severity_badge(self, obj):
        if obj.result and 'severity' in obj.result:
            severity = obj.result['severity']
            colors = {
                'safe': 'green',
                'warning': 'orange',
                'danger': 'red',
                'critical': 'darkred',
                'error': 'gray'
            }
            color = colors.get(severity, 'gray')
            return format_html(
                '<span style="background-color: {}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;">{}</span>',
                color, severity.upper()
            )
        return 'N/A'
    severity_badge.short_description = 'Severity'
    
    def result_preview(self, obj):
        if obj.result:
            import json
            formatted_result = json.dumps(obj.result, indent=2)
            return format_html('<pre style="overflow: auto; max-height: 300px;">{}</pre>', formatted_result)
        return 'No results'
    result_preview.short_description = 'Result Details'

@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    list_display = ('indicator_type', 'pattern', 'severity', 'description_preview')
    list_filter = ('severity', 'indicator_type')
    search_fields = ('indicator_type', 'pattern', 'description')
    list_editable = ('pattern', 'severity')
    list_per_page = 20
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('indicator_type', 'pattern', 'severity')
        }),
        ('Description', {
            'fields': ('description',)
        }),
    )
    
    def severity_badge(self, obj):
        colors = {
            'low': 'gray',
            'medium': 'orange',
            'high': 'red',
            'critical': 'darkred'
        }
        color = colors.get(obj.severity, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;">{}</span>',
            color, obj.get_severity_display().upper()
        )
    severity_badge.short_description = 'Severity'
    
    def description_preview(self, obj):
        return obj.description[:100] + '...' if len(obj.description) > 100 else obj.description
    description_preview.short_description = 'Description'

# Custom admin site header and title
admin.site.site_header = 'PhishGuard Administration'
admin.site.site_title = 'PhishGuard Admin Portal'
admin.site.index_title = 'Welcome to PhishGuard Security Administration'

# Optional: Add custom admin actions
def mark_as_high_severity(modeladmin, request, queryset):
    queryset.update(severity='high')
mark_as_high_severity.short_description = "Mark selected indicators as High severity"

def mark_as_critical_severity(modeladmin, request, queryset):
    queryset.update(severity='critical')
mark_as_critical_severity.short_description = "Mark selected indicators as Critical severity"

# Add actions to ThreatIndicator admin
ThreatIndicatorAdmin.actions = [mark_as_high_severity, mark_as_critical_severity]
