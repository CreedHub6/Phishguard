import requests
import tldextract
import whois
from urllib.parse import urlparse
import re
import time
from datetime import datetime
import socket
from .threat_intelligence import check_threat_intelligence
from .pattern_matcher import check_patterns

def scan_url(url):
    result = {
        'url': url,
        'is_safe': False,
        'score': 100,  # Start with perfect score, deduct for issues
        'warnings': [],
        'domain_info': {},
        'redirects': [],
        'threat_intelligence': {},
        'loading_steps': [],
        'scan_time': 0
    }
    
    start_time = time.time()
    
    try:
        # Check against threat patterns
        pattern_warnings = check_patterns(url)
        result['warnings'].extend(pattern_warnings)
        result['score'] -= len(pattern_warnings) * 10  # Deduct 10 points per warning


        # Simulate scanning steps for UI
        result['loading_steps'].append({'step': 'Initializing scan', 'status': 'completed'})
        
        # Check URL structure
        result['loading_steps'].append({'step': 'Analyzing URL structure', 'status': 'in-progress'})
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url
            parsed_url = urlparse(url)
        
        # Extract domain information
        result['loading_steps'].append({'step': 'Extracting domain information', 'status': 'in-progress'})
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        result['domain_info']['domain'] = domain
        result['domain_info']['subdomain'] = extracted.subdomain
        
        # Check for IP address instead of domain
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, parsed_url.netloc):
            result['warnings'].append({'message': 'URL uses IP address instead of domain name', 'severity': 'medium'})
            result['score'] -= 15
        
        # Check URL length
        if len(url) > 75:
            result['warnings'].append({'message': 'URL is unusually long', 'severity': 'low'})
            result['score'] -= 5
        
        # Check for suspicious characters
        if '@' in url:
            result['warnings'].append({'message': 'URL contains @ symbol (possible deception)', 'severity': 'high'})
            result['score'] -= 20
        
        # Check for multiple subdomains
        if extracted.subdomain.count('.') > 1:
            result['warnings'].append({'message': 'URL has multiple subdomains', 'severity': 'medium'})
            result['score'] -= 10
        
        # Check for hyphens in domain
        if '-' in extracted.domain:
            result['warnings'].append({'message': 'Domain contains hyphens (suspicious)', 'severity': 'low'})
            result['score'] -= 5
        
        # Try to get whois information
        result['loading_steps'].append({'step': 'Checking domain registration', 'status': 'in-progress'})
        try:
            domain_info = whois.whois(domain)
            result['domain_info']['creation_date'] = str(domain_info.creation_date)
            result['domain_info']['expiration_date'] = str(domain_info.expiration_date)
            result['domain_info']['registrar'] = str(domain_info.registrar)
            
            # Check domain age
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age = (datetime.now().date() - creation_date.date()).days
                result['domain_info']['age_days'] = domain_age
                
                if domain_age < 365:
                    result['warnings'].append({
                        'message': f'Domain is relatively new ({domain_age} days)', 
                        'severity': 'medium'
                    })
                    result['score'] -= 15
        except Exception as e:
            result['warnings'].append({
                'message': f'Could not retrieve domain registration information: {str(e)}', 
                'severity': 'low'
            })
        
        # Check for redirects
        result['loading_steps'].append({'step': 'Analyzing redirects', 'status': 'in-progress'})
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            if len(response.history) > 2:
                result['warnings'].append({
                    'message': f'URL redirects multiple times ({len(response.history)} redirects)', 
                    'severity': 'medium'
                })
                result['score'] -= 10
                for resp in response.history:
                    result['redirects'].append({
                        'url': resp.url,
                        'status': resp.status_code
                    })
        except Exception as e:
            result['warnings'].append({
                'message': f'Could not access URL: {str(e)}', 
                'severity': 'medium'
            })
            result['score'] -= 20
        
        # Check threat intelligence
        result['loading_steps'].append({'step': 'Checking threat databases', 'status': 'in-progress'})
        threat_info = check_threat_intelligence(domain)
        result['threat_intelligence'] = threat_info
        if threat_info['is_malicious']:
            result['warnings'].append({
                'message': 'Domain found in threat intelligence databases', 
                'severity': 'critical'
            })
            result['score'] -= 30
        
        # Check for HTTPS
        result['loading_steps'].append({'step': 'Checking security protocols', 'status': 'in-progress'})
        if parsed_url.scheme != 'https':
            result['warnings'].append({
                'message': 'Connection is not using HTTPS (insecure)', 
                'severity': 'high'
            })
            result['score'] -= 20
        
        # Final score calculation
        result['score'] = max(0, min(100, result['score']))  # Ensure score is between 0-100
        
        # Determine safety based on score
        if result['score'] >= 80:
            result['is_safe'] = True
            result['message'] = 'This URL appears to be safe'
            result['severity'] = 'safe'
        elif result['score'] >= 60:
            result['message'] = 'This URL has some concerning characteristics'
            result['severity'] = 'warning'
        elif result['score'] >= 40:
            result['message'] = 'This URL is potentially dangerous'
            result['severity'] = 'danger'
        else:
            result['message'] = 'This URL is highly suspicious and potentially malicious'
            result['severity'] = 'critical'
        
        # Update all steps to completed
        for step in result['loading_steps']:
            step['status'] = 'completed'
            
    except Exception as e:
        result['warnings'].append({
            'message': f'Error analyzing URL: {str(e)}', 
            'severity': 'high'
        })
        result['score'] = 0
        result['message'] = 'Scan failed due to an error'
        result['severity'] = 'error'
    
    result['scan_time'] = round(time.time() - start_time, 2)
    return result
