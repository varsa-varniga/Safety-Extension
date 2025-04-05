# feature_extractor.py
import re
import whois
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc

    # Feature 1: Does the URL contain an IP address?
    features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0

    # Feature 2: Does it use HTTPS?
    features['uses_https'] = 1 if url.lower().startswith("https") else 0

    # Feature 3: Length of URL
    features['url_length'] = len(url)

    # Feature 4: Presence of '@' symbol
    features['has_at_symbol'] = 1 if "@" in url else 0

    # Feature 5: Dash in domain
    features['has_dash'] = 1 if "-" in domain else 0

    # Feature 6: Number of subdomains
    features['subdomain_count'] = len(domain.split(".")) - 2 if domain.count('.') >= 2 else 0

    # Feature 7-9: Keyword indicators
    url_lower = url.lower()
    features['has_login'] = 1 if "login" in url_lower else 0
    features['has_secure'] = 1 if "secure" in url_lower else 0
    features['has_verify'] = 1 if "verify" in url_lower else 0

    # Feature 10: Domain age (in days)
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date

        # Handle list values (some domains return a list of dates)
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]

        if creation and expiration:
            features['domain_age_days'] = (expiration - creation).days
        else:
            features['domain_age_days'] = -1
    except:
        features['domain_age_days'] = -1

    return features
