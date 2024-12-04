import json
from fpdf import FPDF
from collections import Counter


class PDF(FPDF):
    def header(self):
        self.set_font("Arial", size=12, style="B")
        self.cell(0, 10, "Cybersecurity Scan Report", border=0, ln=True, align="C")
        self.ln(10)

    def chapter_title(self, title):
        self.set_font("Arial", size=14, style="B")
        self.cell(0, 10, title, ln=True)
        self.ln(5)

    def add_table(self, data, columns):
        self.set_font("Arial", size=12)
        col_width = self.w / len(columns) - 5  # Adjust column width
        # Add table header
        self.set_font("Arial", size=12, style="B")
        for col in columns:
            self.cell(col_width, 10, col, border=1, align="C")
        self.ln()
        # Add table rows
        self.set_font("Arial", size=12)
        for row in data:
            for col in row:
                self.cell(col_width, 10, str(col), border=1, align="C")
            self.ln()


def sanitize_text(text):
    """Sanitize text for compatibility with FPDF."""
    return text.encode("latin-1", "replace").decode("latin-1")


def generate_pdf():
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Trivy Results
    with open("trivy_scan_results.json") as f:
        trivy_results = json.load(f)
        trivy_data = [
            [
                result["Target"],
                vul["VulnerabilityID"],
                vul["Severity"],
                vul["PkgName"],
                vul.get("InstalledVersion", "N/A"),
                vul.get("FixedVersion", "N/A"),
                sanitize_text(vul["Description"]),
                vul.get("PrimaryURL", "N/A"),
            ]
            for result in trivy_results.get("Results", [])
            for vul in result.get("Vulnerabilities", [])
        ]
        trivy_columns = [
            "Target",
            "Vulnerability ID",
            "Severity",
            "Package Name",
            "Installed Version",
            "Fixed Version",
            "Description",
            "Primary URL",
        ]
        pdf.chapter_title("Trivy Findings")
        if trivy_data:
            pdf.add_table(trivy_data, trivy_columns)
        else:
            pdf.cell(0, 10, "No vulnerabilities detected by Trivy.", ln=True)

    # Detect-Secrets Results
    with open("detect_secrets_audit_results.txt") as f:
        detect_secrets_findings = f.readlines()
    pdf.chapter_title("Detect-Secrets Findings")
    if detect_secrets_findings:
        detect_secrets_data = [[sanitize_text(f)] for f in detect_secrets_findings]
        detect_secrets_columns = ["Secret"]
        pdf.add_table(detect_secrets_data, detect_secrets_columns)
    else:
        pdf.cell(0, 10, "No secrets detected by Detect-Secrets.", ln=True)

    # Semgrep Results
    with open("semgrep_results.json") as f:
        semgrep_results = json.load(f)
        semgrep_data = [
            [
                result["check_id"],
                result["path"],
                result["start"]["line"],
                result["extra"].get("severity", "UNKNOWN"),
                sanitize_text(result["extra"]["message"]),
            ]
            for result in semgrep_results.get("results", [])
        ]
        semgrep_columns = ["Check ID", "File Path", "Line", "Severity", "Message"]
        pdf.chapter_title("Semgrep Findings")
        if semgrep_data:
            pdf.add_table(semgrep_data, semgrep_columns)
        else:
            pdf.cell(0, 10, "No issues detected by Semgrep.", ln=True)

    # Save the PDF
    pdf.output("security_scan_report.pdf")


if __name__ == "__main__":
    generate_pdf()
