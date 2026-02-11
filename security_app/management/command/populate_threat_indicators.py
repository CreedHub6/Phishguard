from django.core.management.base import BaseCommand
from security_app.models import ThreatIndicator

class Command(BaseCommand):
    help = 'Populates the database with common threat indicators'
    
    def handle(self, *args, **options):
        indicators = [
            {
                'indicator_type': 'IP Address',
                'pattern': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                'description': 'URL uses IP address instead of domain name',
                'severity': 'medium'
            },
            {
                'indicator_type': 'Long URL',
                'pattern': '.{75,}',
                'description': 'URL is unusually long (more than 75 characters)',
                'severity': 'low'
            },
            {
                'indicator_type': '@ Symbol',
                'pattern': '@',
                'description': 'URL contains @ symbol (possible deception attempt)',
                'severity': 'high'
            },
            {
                'indicator_type': 'Multiple Subdomains',
                'pattern': r'^(https?://)?([a-z0-9-]+\.){3,}',
                'description': 'URL has multiple subdomains (suspicious pattern)',
                'severity': 'medium'
            },
            {
                'indicator_type': 'Hyphenated Domain',
                'pattern': r'[a-z0-9-]+-[a-z0-9-]+\.[a-z]{2,}',
                'description': 'Domain contains multiple hyphens (suspicious)',
                'severity': 'low'
            },
            {
                'indicator_type': 'HTTPS Missing',
                'pattern': '^http://',
                'description': 'Connection is not using HTTPS (insecure)',
                'severity': 'high'
            },
            {
                'indicator_type': 'Suspicious TLD',
                'pattern': r'\.(xyz|cc|top|club|gq|ml|tk|cf)$',
                'description': 'URL uses suspicious top-level domain',
                'severity': 'medium'
            },
            {
                'indicator_type': 'Phishing Keywords',
                'pattern': r'(login|verify|account|secure|bank|paypal|update)',
                'description': 'URL contains common phishing keywords',
                'severity': 'high'
            },
        ]
        
        created_count = 0
        for indicator_data in indicators:
            indicator, created = ThreatIndicator.objects.get_or_create(
                indicator_type=indicator_data['indicator_type'],
                defaults=indicator_data
            )
            if created:
                created_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully populated {created_count} threat indicators'
            )
        )
