import re
from ..models import ThreatIndicator

def check_patterns(url):
    """
    Check URL against all threat indicator patterns
    """
    warnings = []
    
    indicators = ThreatIndicator.objects.all()
    
    for indicator in indicators:
        try:
            if re.search(indicator.pattern, url, re.IGNORECASE):
                warnings.append({
                    'message': indicator.description,
                    'severity': indicator.severity
                })
        except re.error:
            # Handle invalid regex patterns
            continue
    
    return warnings
