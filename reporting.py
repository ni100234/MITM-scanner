import os
import datetime

def generate_report():
    report_folder = "report"
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    report_filename = os.path.join(report_folder, f"report_{datetime.datetime.now():%Y%m%d_%H%M%S}.html")
    
    with open(report_filename, 'w') as report_file:
        # Write HTML header
        report_file.write("<html>\n<head>\n<title>Network Security Report</title>\n")
        report_file.write("<style>\nbody { font-family: Arial, sans-serif; background-color: #f0f0f0; padding: 20px; }\n")
        report_file.write(".container { max-width: 1200px; margin: 0 auto; }\n")
        report_file.write("h1, h2, h3 { color: #714674; }\n")
        report_file.write("h1 { font-size: 28px; margin-bottom: 20px; }\n")
        report_file.write("h2 { margin-top: 40px; border-bottom: 1px solid #cccccc; padding-bottom: 10px; font-size: 24px; }\n")
        report_file.write("h3 { margin-top: 20px; font-size: 20px; }\n")
        report_file.write("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n")
        report_file.write("th, td { border: 1px solid #dddddd; text-align: left; padding: 12px; font-size: 16px; }\n")
        report_file.write("th { background-color: #f2f2f2; }\n")
        report_file.write(".highlight-green { background-color: #d4edda; color: #155724; }\n")
        report_file.write(".highlight-red { background-color: #f8d7da; color: #721c24; }\n")
        report_file.write(".highlight-orange { background-color: #fff3cd; color: #856404; }\n")
        report_file.write(".section { margin-bottom: 30px; }\n")
        report_file.write(".state-open { font-size: 18px; font-weight: bold; color: #007bff; }\n")
        report_file.write(".log-entry { font-size: 14px; }\n")
        report_file.write(".log-entry:nth-child(odd) { background-color: #f9f9f9; }\n")
        report_file.write(".log-entry:nth-child(even) { background-color: #ffffff; }\n")
        report_file.write(".report-info { float: right; font-size: 14px; }\n")
        report_file.write(".remediation { color: #82C26E; }\n")
        report_file.write("</style>\n</head>\n<body>\n")
        
        # Write report title and info
        report_file.write("<div class='container'>\n")
        report_file.write(f"<h1>Network Security Report</h1>\n")
        report_file.write(f"<div class='report-info'>Report: {os.path.basename(report_filename)}</div>\n")
        report_file.write(f"<div class='report-info'>Created: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}</div>\n")
        
        # Include Network Scanning Results
        network_scan_file = os.path.join("last_scan", "network_scanning.txt")
        if os.path.exists(network_scan_file):
            report_file.write("<div class='section'>\n")
            report_file.write("<h2>Network Scanning Results</h2>\n")
            report_file.write("<pre style='font-size: 18px;'>\n")
            with open(network_scan_file, 'r') as f:
                for line in f:
                    if "state:open" in line.lower():
                        report_file.write(f"<span class='state-open'>{line.strip()}</span>\n")
                    else:
                        report_file.write(f"{line.strip()}\n")
            report_file.write("</pre>\n")
            report_file.write(f"<p class='log-entry'>{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - Last log entry: Network Scanning Results</p>\n")
            report_file.write("</div>\n")
        else:
            report_file.write("<div class='section'>\n")
            report_file.write("<h2>Network Scanning Results</h2>\n")
            report_file.write("<p>No network scanning results found.</p>\n")
            report_file.write("</div>\n")
        
        # Write MITM Detection Results
        report_file.write("<div class='section'>\n")
        report_file.write("<h2>MITM Detection Results</h2>\n")
        report_file.write("<table>\n<tr><th>Result</th><th>Remediation</th></tr>\n")
        
        mitm_file = os.path.join("last_scan", "mitm_detection.txt")
        if os.path.exists(mitm_file):
            with open(mitm_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if "MITM detected" in line:
                        report_file.write(f"<tr><td class='highlight-red'>{line.strip()}</td><td class='remediation'>Implement strict HTTPS enforcement, use HSTS, and regularly audit TLS certificates.</td></tr>\n")
                    else:
                        report_file.write(f"<tr><td class='highlight-orange'>{line.strip()}</td><td class='remediation'>Ensure secure network configurations and monitor for unusual network behavior.</td></tr>\n")
            if lines:
                report_file.write(f"<p class='log-entry'>{lines[-1].strip()}</p>\n")
        else:
            report_file.write("<tr><td colspan='2'>No MITM detection results found.</td></tr>\n")
        
        report_file.write("</table>\n")
        report_file.write("</div>\n")
        
        # Write Secure Protocols Check Results
        report_file.write("<div class='section'>\n")
        report_file.write("<h2>Secure Protocols Check Results</h2>\n")
        report_file.write("<table>\n<tr><th>Result</th><th>Remediation</th></tr>\n")
        
        secure_protocol_file = os.path.join("last_scan", "secure_protocol.txt")
        if os.path.exists(secure_protocol_file):
            with open(secure_protocol_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    report_file.write(f"<tr><td>{line.strip()}</td><td class='remediation'>Ensure all services are configured to use secure protocols (e.g., HTTPS, TLS) and disable insecure protocols.</td></tr>\n")
            if lines:
                report_file.write(f"<p class='log-entry'>{lines[-1].strip()}</p>\n")
        else:
            report_file.write("<tr><td colspan='2'>No secure protocols check results found.</td></tr>\n")
        
        report_file.write("</table>\n")
        report_file.write("</div>\n")
        
        # Write Endpoint Verification Results
        report_file.write("<div class='section'>\n")
        report_file.write("<h2>Endpoint Verification Results</h2>\n")
        report_file.write("<table>\n<tr><th>Result</th><th>Remediation</th></tr>\n")
        
        endpoint_file = os.path.join("last_scan", "endpoint_verification.txt")
        if os.path.exists(endpoint_file):
            with open(endpoint_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    report_file.write(f"<tr><td>{line.strip()}</td><td class='remediation'>Regularly verify endpoint security configurations and apply patches and updates promptly.</td></tr>\n")
            if lines:
                report_file.write(f"<p class='log-entry'>{lines[-1].strip()}</p>\n")
        else:
            report_file.write("<tr><td colspan='2'>No endpoint verification results found.</td></tr>\n")
        
        report_file.write("</table>\n")
        report_file.write("</div>\n")
        
        # Write Last 50 Log Entries with alternating colors
        report_file.write("<div class='section'>\n")
        report_file.write("<h2>Last 50 Log Entries</h2>\n")
        report_file.write("<table>\n<tr><th>Log Entry</th></tr>\n")
        
        log_file = os.path.join("logs", "log.txt")
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines[-50:], 1):
                    if i % 2 == 0:
                        report_file.write(f"<tr><td class='log-entry' style='background-color: #f9f9f9;'>{line.strip()}</td></tr>\n")
                    else:
                        report_file.write(f"<tr><td class='log-entry'>{line.strip()}</td></tr>\n")
                if lines:
                    report_file.write(f"<p class='log-entry'>{lines[-1].strip()}</p>\n")
        else:
            report_file.write("<tr><td>No log entries found.</td></tr>\n")
        
        report_file.write("</table>\n")
        report_file.write("</div>\n")
        
        # Write HTML footer
        report_file.write("</div>\n")  # close container
        report_file.write("</body>\n</html>\n")
    

# Test function
if __name__ == "__main__":
    generate_report()
