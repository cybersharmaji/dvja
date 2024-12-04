import json
from fpdf import FPDF

# Initialize PDF
pdf = FPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()
pdf.set_font("Arial", size=12)

# Title
pdf.set_font("Arial", size=16, style="B")
pdf.cell(0, 10, "Cybersecurity Scan Report", ln=True, align="C")
pdf.ln(10)

# Function to add findings
def add_findings(tool_name, findings):
    pdf.set_font("Arial", size=14, style="B")
    pdf.cell(0, 10, f"{tool_name} Findings", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", size=12)
    if findings:
        for finding in findings:
            pdf.multi_cell(0, 10, f"- {finding}")
            pdf.ln(2)
    else:
        pdf.cell(0, 10, "No findings detected.", ln=True)
    pdf.ln(10)

# Trivy Results
with open("trivy_scan_results.json") as f:
    trivy_results = json.load(f)
    trivy_findings = [
        f"Target: {result['Target']}, Vulnerability: {vul['VulnerabilityID']} - {vul['Description']}"
        for result in trivy_results.get("Results", [])
        for vul in result.get("Vulnerabilities", [])
    ]
add_findings("Trivy", trivy_findings)

# Detect-Secrets Results
with open("detect_secrets_audit_results.txt") as f:
    detect_secrets_findings = f.readlines()
add_findings("Detect-Secrets", detect_secrets_findings)

# Semgrep Results
with open("semgrep_results.json") as f:
    semgrep_results = json.load(f)
    semgrep_findings = [
        f"Check: {result['check_id']}, Path: {result['path']}, Line: {result['start']['line']}, Severity: {result['extra'].get('severity', 'UNKNOWN')} - {result['extra']['message']}"
        for result in semgrep_results.get("results", [])
    ]
add_findings("Semgrep", semgrep_findings)

# Save PDF
pdf.output("security_scan_report.pdf")
