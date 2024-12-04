import json
from fpdf import FPDF
import matplotlib.pyplot as plt
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

    def add_image(self, image_path, title):
        self.add_page()
        self.chapter_title(title)
        self.image(image_path, x=10, y=self.get_y(), w=180)
        self.ln(10)


def sanitize_text(text):
    """Sanitize text for compatibility with FPDF."""
    return text.encode("latin-1", "replace").decode("latin-1")


def plot_vulnerabilities_by_severity(data, output_path, title="Vulnerabilities by Severity"):
    """Generate a bar chart for vulnerabilities by severity."""
    severity_counter = Counter([item["Severity"] for item in data])
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = [severity_counter.get(sev, 0) for sev in severities]

    plt.figure(figsize=(10, 6))
    plt.bar(severities, counts, color=["red", "orange", "yellow", "green"])
    plt.title(title)
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.savefig(output_path)
    plt.close()


def generate_pdf():
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Trivy Results
    with open("trivy_scan_results.json") as f:
        trivy_results = json.load(f)
        trivy_data = [
            {
                "Target": result["Target"],
                "VulnerabilityID": vul["VulnerabilityID"],
                "Severity": vul["Severity"],
                "PkgName": vul["PkgName"],
                "InstalledVersion": vul.get("InstalledVersion", "N/A"),
                "FixedVersion": vul.get("FixedVersion", "N/A"),
                "Description": sanitize_text(vul["Description"]),
                "PrimaryURL": vul.get("PrimaryURL", "N/A"),
            }
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
        trivy_table_data = [
            [item[col] for col in trivy_columns] for item in trivy_data
        ]
        pdf.chapter_title("Trivy Findings")
        if trivy_table_data:
            pdf.add_table(trivy_table_data, trivy_columns)
            # Plot Trivy vulnerabilities by severity
            plot_vulnerabilities_by_severity(trivy_data, "trivy_vulnerabilities.png")
            pdf.add_image("trivy_vulnerabilities.png", "Trivy Vulnerabilities by Severity")
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
            {
                "CheckID": result["check_id"],
                "FilePath": result["path"],
                "Line": result["start"]["line"],
                "Severity": result["extra"].get("severity", "UNKNOWN"),
                "Message": sanitize_text(result["extra"]["message"]),
            }
            for result in semgrep_results.get("results", [])
        ]
        semgrep_columns = ["Check ID", "File Path", "Line", "Severity", "Message"]
        semgrep_table_data = [
            [item[col] for col in semgrep_columns] for item in semgrep_data
        ]
        pdf.chapter_title("Semgrep Findings")
        if semgrep_table_data:
            pdf.add_table(semgrep_table_data, semgrep_columns)
            # Plot Semgrep vulnerabilities by severity
            plot_vulnerabilities_by_severity(semgrep_data, "semgrep_vulnerabilities.png")
            pdf.add_image("semgrep_vulnerabilities.png", "Semgrep Vulnerabilities by Severity")
        else:
            pdf.cell(0, 10, "No issues detected by Semgrep.", ln=True)

    # Save the PDF
    pdf.output("security_scan_report.pdf")


if __name__ == "__main__":
    generate_pdf()
