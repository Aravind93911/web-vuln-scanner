import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        print("[!] Website is not using HTTPS.")
    else:
        print("[+] HTTPS is enabled.")

def check_security_headers(response):
    print("\n[+] Checking Security Headers...")
    for header in SECURITY_HEADERS:
        if header in response.headers:
            print(f"[+] {header} is present.")
        else:
            print(f"[!] {header} is missing.")

def get_all_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")
        print(f"\n[+] Detected {len(forms)} form(s) on page.")
        return forms
    except requests.RequestException as e:
        print(f"[!] Failed to retrieve page: {e}")
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def analyze_forms(forms):
    print("\n[+] Analyzing Forms...")
    for i, form in enumerate(forms, start=1):
        details = get_form_details(form)
        print(f"\n--- Form #{i} ---")
        print(f"Action: {details['action']}")
        print(f"Method: {details['method'].upper()}")
        print("Inputs:")
        for input_field in details["inputs"]:
            print(f"  - Name: {input_field['name']}, Type: {input_field['type']}")

def scan(url):
    print(f"\nScanning: {url}")
    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Could not connect: {e}")
        return

    check_https(url)
    check_security_headers(response)

    forms = get_all_forms(url)
    analyze_forms(forms)

    print("\n[✓] Scan completed.")

if __name__ == "__main__":
    target = input("Enter URL (e.g., https://example.com): ")
    scan(target)
