import re
import requests
from bs4 import BeautifulSoup

def analyze_email(content):
    result = {
        'is_phishing': False,
        'warnings': [],
        'details': {}
    }
    
    # Check for suspicious keywords
    suspicious_keywords = [
        'urgent', 'verify', 'account', 'suspended', 'password', 'login',
        'confirm', 'bank', 'paypal', 'security', 'alert', 'update',
        'limited time', 'offer', 'prize', 'winner', 'free', 'gift',
        'click here', 'below', 'dear customer', 'dear user'
    ]
    
    content_lower = content.lower()
    found_keywords = []
    for keyword in suspicious_keywords:
        if keyword in content_lower:
            found_keywords.append(keyword)
    
    if found_keywords:
        result['warnings'].append(f"Suspicious keywords detected: {', '.join(found_keywords)}")
        result['details']['suspicious_keywords'] = found_keywords
    
    # Check for links in email
    link_pattern = r'https?://[^\s]+'
    links = re.findall(link_pattern, content)
    
    if links:
        result['details']['links'] = links
        result['warnings'].append(f"Email contains {len(links)} links - be cautious about clicking them")
    
    # Check for HTML content
    if '<html' in content_lower or '<body' in content_lower:
        result['warnings'].append('Email contains HTML content - could be hiding malicious code')
        
        # Try to extract text from HTML
        try:
            soup = BeautifulSoup(content, 'html.parser')
            text_content = soup.get_text()
            result['details']['text_content'] = text_content[:500] + '...' if len(text_content) > 500 else text_content
        except:
            pass
    
    # Check for attachments mentioned
    attachment_pattern = r'attachment|download|file|\.exe|\.zip|\.rar|\.pdf|\.doc'
    if re.search(attachment_pattern, content_lower):
        result['warnings'].append('Email mentions attachments - be cautious about downloading files')
    
    # Check for sender spoofing indicators
    if 'from:' in content_lower:
        # Simple check for mismatched sender info
        from_lines = [line for line in content.split('\n') if line.lower().startswith('from:')]
        if from_lines:
            result['details']['from_header'] = from_lines[0]
    
    # Check for generic greetings
    generic_greetings = ['dear customer', 'dear user', 'dear valued', 'dear member', 'dear account holder']
    if any(greeting in content_lower for greeting in generic_greetings):
        result['warnings'].append('Email uses generic greeting instead of your name')
    
    # Determine if phishing
    if len(result['warnings']) > 2:
        result['is_phishing'] = True
        result['verdict'] = 'This email is likely a phishing attempt'
    elif len(result['warnings']) > 0:
        result['verdict'] = 'This email shows some suspicious characteristics'
    else:
        result['verdict'] = 'No obvious phishing indicators detected'
    
    return result
