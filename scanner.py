# scanner.py
import requests
from utils import make_request, discover_forms, discover_inputs, check_open_redirect
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Function to check for SQL Injection vulnerabilities
def check_sql_injection(url):
    payload = "' OR '1'='1"
    vulnerable_urls = []
    response = make_request(url + payload)
    if response and ("syntax error" in response.text.lower() or "mysql" in response.text.lower()):
        vulnerable_urls.append(url)
    return vulnerable_urls

# Function to check for XSS vulnerabilities
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    vulnerable_urls = []
    response = make_request(url)
    if response and payload in response.text:
        vulnerable_urls.append(url)
    return vulnerable_urls

# Function to check for CSRF vulnerabilities
def check_csrf(url):
    response = make_request(url)
    if response and "csrf_token" not in response.text:
        return [url]  # CSRF Vulnerability found
    return []

# Function to check for Directory Traversal vulnerabilities
def check_directory_traversal(url):
    payloads = ["/../../../../etc/passwd", "/..\\..\\..\\..\\..\\windows\\win.ini"]
    vulnerable_urls = []
    for payload in payloads:
        response = make_request(url + payload)
        if response and ("root:x" in response.text or "win.ini" in response.text):
            vulnerable_urls.append(url + payload)
    return vulnerable_urls

# Function to scan for open redirects
def scan_open_redirect(url):
    if check_open_redirect(url):
        return [url]
    return []

# Function to check HTTP Headers for security vulnerabilities
def check_http_headers(url):
    headers = ["X-Content-Type-Options", "X-XSS-Protection", "Strict-Transport-Security"]
    missing_headers = []
    response = make_request(url)
    if response:
        for header in headers:
            if header not in response.headers:
                missing_headers.append(header)
    return missing_headers

# Function to scan a single URL for vulnerabilities
def scan_url(url):
    results = {
        "url": url,
        "sql_injection": check_sql_injection(url),
        "xss": check_xss(url),
        "csrf": check_csrf(url),
        "directory_traversal": check_directory_traversal(url),
        "open_redirect": scan_open_redirect(url),
        "http_headers": check_http_headers(url)
    }
    return results

# Function to run the scan on multiple URLs concurrently
def run_scan(urls):
    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(scan_url, url): url for url in urls}
        for future in future_to_url:
            url = future_to_url[future]
            result = future.result()
            results[url] = result
    return results

# Function to generate a HTML report
def generate_html_report(results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_report_{timestamp}.html"
    
    with open(filename, "w") as file:
        file.write("<html><body><h1>Web Application Security Scan Report</h1>")
        
        for url, issues in results.items():
            file.write(f"<h2>{url}</h2>")
            for issue, details in issues.items():
                if details:
                    file.write(f"<p><strong>{issue}:</strong><br>{details}</p>")
                else:
                    file.write("<p>No vulnerabilities found</p>")
        file.write("</body></html>")
    print(f"Report saved to {filename}")

if __name__ == "__main__":
    # Example URLs to scan
    urls = ["http://example.com", "http://test.com"]
    
    # Run the scan
    results = run_scan(urls)
    
    # Generate the report
    generate_html_report(results)
