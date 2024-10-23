import re
import datetime
import urllib.parse
import ipaddress
import requests
import os
from dotenv import load_dotenv

"""
SOHAN's Enhanced Phishing URL Detector
Credit for this project goes to SOHAN.
Enhanced with VirusTotal API integration.
"""

load_dotenv()  # Load environment variables from .env file

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def check_phishing_url(url):
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc

    # Check for IP address instead of domain name
    if is_ip_address(domain):
        return True, "IP address used instead of domain name"

    # Check for phishing keywords
    phishing_keywords = ['login', 'secure', 'account', 'verify', 'update']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return True, "Phishing keyword detected"

    # Check for blacklisted domains (hardcoded for simplicity)
    blacklist = ['evil.com', 'phishing.com', 'fake-bank.com']
    if domain in blacklist:
        return True, "Blacklisted domain"

    # Check for suspicious URL patterns
    if len(url) > 100:
        return True, "Suspiciously long URL"

    # Check for misspelled brand names (example: 'paypaI' instead of 'paypal')
    brand_names = ['paypal', 'amazon', 'google', 'facebook', 'microsoft']
    for brand in brand_names:
        if brand in domain and not domain.startswith(brand):
            return True, f"Possible typosquatting of {brand}"

    # Check with VirusTotal API
    vt_result = check_virustotal(url)
    if vt_result:
        return True, f"VirusTotal detection: {vt_result}"

    return False, "URL appears safe"

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        print("VirusTotal API key not found. Skipping VirusTotal check.")
        return None

    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}

    try:
        response = requests.get(api_url, params=params)
        result = response.json()

        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            if positives > 0:
                return f"{positives}/{total} scanners detected this as malicious"
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")

    return None

def log_result(url, is_phishing, reason):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "PHISHING" if is_phishing else "SAFE"
    log_entry = f"{timestamp} | {status} | {url} | {reason}\n"
    
    with open("url_log.txt", "a") as log_file:
        log_file.write(log_entry)

def main():
    print("SOHAN's Enhanced Phishing URL Detector")
    print("Credit for this project goes to SOHAN.")
    print("Enhanced with VirusTotal API integration.")
    print()
    while True:
        url = input("Enter a URL to check (or 'quit' to exit): ")
        if url.lower() == 'quit':
            break

        is_phishing, reason = check_phishing_url(url)
        log_result(url, is_phishing, reason)

        if is_phishing:
            print(f"WARNING: Potential phishing URL detected! Reason: {reason}")
        else:
            print("The URL appears to be safe.")

        print("Result has been logged.")
        print()

if __name__ == "__main__":
    main()