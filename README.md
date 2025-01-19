# Vulnerability Scanner

This project is a multi-threaded vulnerability scanner designed to detect common security vulnerabilities in web applications. The scanner supports a variety of attack vectors, including SQL Injection, XSS, CSRF, File Upload, and more. Results are logged and reported in multiple formats for ease of analysis.

## Features

- **Multi-threaded scanning** for improved efficiency.
- **Detection of common vulnerabilities**, including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - File Upload vulnerabilities
  - Directory Traversal
  - HTTP Response Splitting
  - Command Injection
  - File Inclusion
  - Server Misconfigurations
- **Logging** of detected vulnerabilities with severity levels.
- **Reports** generated in CSV, JSON, and HTML formats.
- **Pie chart visualization** of vulnerability distribution.

## Prerequisites

- Python 3.x
- Required Python libraries (install via pip):
  ```bash
  pip install requests matplotlib
  ```
- Internet connection for testing HTTP requests.

## Setup and Installation

1. Clone the repository or copy the project files to your local machine.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Update the target URLs and vulnerability types in the script as required.
2. Run the scanner:
   ```bash
   python scanner.py
   ```
3. Results will be logged in the following formats:
   - **Log file**: `vulnerability_scanner.log`
   - **CSV report**: `vulnerability_report.csv`
   - **HTML report**: `vulnerability_report.html`
   - **JSON report**: `vulnerability_report.json`

## Supported Vulnerabilities

1. **SQL Injection**
   - Tests for SQL error indicators using payloads like `' OR 1=1 --`.

2. **XSS (Cross-Site Scripting)**
   - Tests for reflected XSS vulnerabilities using payloads like `<script>alert('XSS')</script>`.

3. **CSRF (Cross-Site Request Forgery)**
   - Simulates CSRF attacks with forged requests.

4. **File Upload Vulnerabilities**
   - Tests for the ability to upload and execute malicious files.

5. **Directory Traversal**
   - Attempts to access restricted files using payloads like `../../../etc/passwd`.

6. **HTTP Response Splitting**
   - Tests for response splitting vulnerabilities using payloads like `\r\nSet-Cookie: test=1`.

7. **Command Injection**
   - Executes OS-level commands using payloads like `; ls` or `| id`.

8. **File Inclusion**
   - Checks for local and remote file inclusion vulnerabilities.

9. **Server Misconfigurations**
   - Tests server methods like `DELETE`, `PUT`, and `TRACE`.

10. **Security Headers**
    - Checks for the presence of essential security headers like `X-Content-Type-Options`.

## Multi-Threading

The scanner uses a queue-based threading model to test multiple URLs and vulnerabilities concurrently, significantly improving scan efficiency.

## Generating Reports

### Pie Chart Visualization
A pie chart is generated to visualize the distribution of detected vulnerabilities. The chart is saved as `vulnerability_distribution.png`.

### CSV Report
The CSV report includes columns for:
- Vulnerability Type
- URL
- Payload
- Severity

### HTML and JSON Reports
- The HTML report is a simple tabular view of the detected vulnerabilities.
- The JSON report provides a structured data format for programmatic use.

## Logging
Detailed logs of the scan process and detected vulnerabilities are stored in `vulnerability_scanner.log`.

## Future Enhancements
- Add support for additional vulnerability types.
- Enhance reporting with more detailed analysis.
- Integrate with vulnerability management tools.

## Disclaimer
This tool is for educational purposes only. Unauthorized use against websites without prior permission is illegal and unethical.

## License
This project is licensed under the MIT License. See the LICENSE file for details.


