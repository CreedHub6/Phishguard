from django.db import models
from django.contrib.auth.models import User

class ScanHistory(models.Model):
    SCAN_TYPES = (
        ('url', 'URL Scan'),
        ('email', 'Email Scan'),
        ('password', 'Password Check'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    content = models.TextField()
    result = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.scan_type} scan at {self.created_at}"

class ThreatIndicator(models.Model):
    indicator_type = models.CharField(max_length=50)
    pattern = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=(
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ))
    
    def __str__(self):
        return self.indicator_type
