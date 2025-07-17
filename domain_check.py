import re
import whois
import requests
from datetime import datetime


def is_valid_email(email):
    """Validate email format."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None


def is_suspicious_email(email):
    if not is_valid_email(email):
        return True, "Invalid email format"

    # Extract the domain from the email
    domain = email.split('@')[-1]

    # Check for suspicious patterns
    if re.search(r'\d', domain):
        return True, "Domain contains numbers, suspicious pattern"

    # Check domain registration date (WHOIS lookup)
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Take the first date if it's a list

        if creation_date is not None:
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 180:
                return True, f"Domain is very new, created {domain_age} days ago"
    except Exception as e:
        return True, f"WHOIS lookup failed: {str(e)}"

    # Check domain reputation with an external service
    response = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyD5jYKEP7wkHkfjuGzna6J2Cmdjf8wgGu4",
        json={
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{domain}"}]  # Ensure the URL is formatted correctly
            }
        }
    )

    print("Response Status Code:", response.status_code)  # Print status code
    print("Response Text:", response.text)  # Print response text

    if response.status_code != 200:
        return True, f"Error with API call: {response.status_code} - {response.text}"

    try:
        result = response.json()
        if result.get("matches"):
            return True, "Domain has a bad reputation"
    except ValueError:
        return True, "Error parsing JSON response"

    return False, "Email looks safe"
