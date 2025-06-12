# Web Vulnerability Scanner

This Python tool scans a web application for common vulnerabilities such as **SQL Injection** and **Cross-Site Scripting (XSS)**.

## Features

- Detects SQL Injection via URL parameters
- Detects XSS via HTML form inputs
- Uses `requests` and `BeautifulSoup` for HTTP requests and HTML parsing

## Requirements

Install the required Python libraries:

```bash
pip install requests beautifulsoup4
```

## Usage

Run the scanner by passing a target URL:

```bash
python web_vuln_scanner.py
```

Example:

```bash
python web_vuln_scanner.py
# Enter URL to scan: http://testphp.vulnweb.com
```

## Disclaimer

This tool is for **educational and ethical testing purposes only**. Do not scan systems without proper authorization.