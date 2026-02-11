import re
from datetime import datetime

def check_password_strength(password):
    result = {
        'score': 0,
        'strength': 'Very Weak',
        'feedback': [],
        'length': len(password)
    }
    
    # Length check
    if len(password) >= 8:
        result['score'] += 1
    else:
        result['feedback'].append('Password should be at least 8 characters long')
    
    # Upper and lower case check
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        result['score'] += 1
    else:
        result['feedback'].append('Password should contain both uppercase and lowercase letters')
    
    # Digit check
    if re.search(r'\d', password):
        result['score'] += 1
    else:
        result['feedback'].append('Password should contain at least one digit')
    
    # Special character check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        result['score'] += 1
    else:
        result['feedback'].append('Password should contain at least one special character')
    
    # Common password check (simplified)
    common_passwords = ['password', '123456', 'qwerty', 'letmein', 'welcome', 'admin', 'monkey']
    if password.lower() in common_passwords:
        result['score'] = 0
        result['feedback'].append('This is a very common password that is easily guessable')
    
    # Determine strength based on score
    if result['score'] == 0:
        result['strength'] = 'Very Weak'
    elif result['score'] == 1:
        result['strength'] = 'Weak'
    elif result['score'] == 2:
        result['strength'] = 'Medium'
    elif result['score'] == 3:
        result['strength'] = 'Strong'
    else:
        result['strength'] = 'Very Strong'
        
    # Calculate time to crack (very rough estimate)
    # This is a simplified calculation for demonstration purposes
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
    
    if charset_size > 0:
        # Very rough estimate: 10^9 attempts per second
        possible_combinations = charset_size ** len(password)
        seconds_to_crack = possible_combinations / 1000000000
        
        # Convert to readable time
        if seconds_to_crack < 60:
            time_str = f"{seconds_to_crack:.2f} seconds"
        elif seconds_to_crack < 3600:
            time_str = f"{seconds_to_crack/60:.2f} minutes"
        elif seconds_to_crack < 86400:
            time_str = f"{seconds_to_crack/3600:.2f} hours"
        elif seconds_to_crack < 31536000:
            time_str = f"{seconds_to_crack/86400:.2f} days"
        else:
            time_str = f"{seconds_to_crack/31536000:.2f} years"
        
        result['time_to_crack'] = time_str
    else:
        result['time_to_crack'] = "instantly"
    
    return result
