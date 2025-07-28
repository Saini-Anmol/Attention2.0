import requests
import re
import google.generativeai as genai
import os
import subprocess
import json
import pypdf
from io import BytesIO
import time
from fpdf import FPDF

# --- PROMPTS ---
EXTRACTION_PROMPT = """
You are a security data extraction tool. From the following Nessus report text, extract all vulnerability findings.
For each finding, you MUST format it on a new line exactly like this:
CVE-ID | CVSS Score | Specific Vulnerability (e.g., "Path Traversal", max 15 words) | Specific Solution (e.g., "Upgrade to 18.19.1")
"""
SUMMARY_PROMPT = """
You are a security analyst. Consolidate the provided list of vulnerability findings into a high-level executive summary.
Your task is to group similar vulnerabilities to reduce redundancy.
Instructions:
1. Group all findings related to the same software (e.g., "Node.js") under a single heading.
2. For each group, provide a single, overarching solution.
3. List the individual vulnerabilities within that group in a table.
4. List any other unique, non-grouped vulnerabilities separately.
5. Provide a brief statistical overview at the top.
"""

# --- Configuration & Model ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
genai_model = None

def configure_gemini(api_key):
    global genai_model
    try:
        genai.configure(api_key=api_key)
        genai_model = genai.GenerativeModel('gemini-1.5-flash')
        return True
    except Exception as e:
        print(f"Error configuring Gemini: {e}")
        return False

# --- PDF Generation ---
def create_project_pdf(chat_history):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Chat History", 0, 1, 'C')
    pdf.set_font("Arial", '', 11)
    for msg in chat_history:
        role = msg['role'].capitalize()
        content = msg['content']
        pdf.set_font("Arial", 'B', 11)
        pdf.multi_cell(0, 5, f"{role}:")
        pdf.set_font("Arial", '', 11)
        pdf.multi_cell(0, 5, content.encode('latin-1', 'replace').decode('latin-1'))
        pdf.ln(5)
    return pdf.output(dest='S').encode('latin-1')


# --- PDF PARSERS ---
def process_nessus_pdf_locally(pdf_file_bytes):
    try:
        pdf_reader = pypdf.PdfReader(BytesIO(pdf_file_bytes))
        full_text = ""
        for page in pdf_reader.pages:
            full_text += page.extract_text() + " \n"

        vulnerability_blocks = re.split(r'(?=\n\d{5,6}\s*-\s*)', full_text)
        findings = []
        for block in vulnerability_blocks[1:]:
            if not block.strip(): continue
            full_title_match = re.match(r'\n(\d{5,6}\s*-\s*.*?)\nSynopsis', block, re.DOTALL)
            full_title = full_title_match.group(1).strip().replace('\n', ' ') if full_title_match else "N/A"
            risk_factor_pattern = re.compile(r"Risk Factor\s*\n(.*?)\n", re.DOTALL)
            cvss_pattern = re.compile(r"CVSS v\d\.\d Base Score\s*[:\n\s]*(\d{1,2}\.\d)")
            cve_pattern = re.compile(r'CVE[-‑]\d{4}[-‑]\d{4,7}')
            solution_pattern = re.compile(r"Solution\s*\n(.*?)\n", re.DOTALL)
            risk_factor = risk_factor_pattern.search(block)
            cvss = cvss_pattern.search(block)
            cves = cve_pattern.findall(block)
            solution = solution_pattern.search(block)
            findings.append({
                "title": full_title,
                "risk_factor": risk_factor.group(1).strip() if risk_factor else "N/A",
                "cvss": float(cvss.group(1)) if cvss else 0.0,
                "cves": ", ".join(sorted(list(set(cves)))) if cves else "N/A",
                "solution": solution.group(1).strip().replace('\n', ' ') if solution else "N/A"
            })
        if not findings: return "No vulnerabilities could be parsed."
        scannable_findings = [f for f in findings if f['risk_factor'].lower() not in ["none", "n/a"]]
        total_vulns = len(scannable_findings)
        critical = [f for f in scannable_findings if f['risk_factor'] == "Critical"]
        high = [f for f in scannable_findings if f['risk_factor'] == "High"]
        medium = [f for f in scannable_findings if f['risk_factor'] == "Medium"]
        sorted_findings = sorted(scannable_findings, key=lambda x: x['cvss'], reverse=True)
        report = f"### Nessus Report Analysis (Local Parser)\n\n**Total Actionable Vulnerabilities Found:** {total_vulns}\n- **Critical:** {len(critical)}\n- **High:** {len(high)}\n- **Medium:** {len(medium)}\n\n---\n\n#### Full Vulnerability Listing (Sorted by Severity):\n| Risk | CVSS | Vulnerability Title | Solution | Associated CVEs |\n|---|---|---|---|---|\n"
        for vuln in sorted_findings:
            report += f"| {vuln['risk_factor']} | {vuln['cvss']} | {vuln['title'].replace('|', ' ')} | {vuln['solution'].replace('|', ' ')} | {vuln['cves']} |\n"
        return report
    except Exception as e:
        return f"An error occurred during local PDF processing: {e}"

def process_nessus_pdf_gemini(pdf_file_bytes, api_key):
    if not genai_model and not configure_gemini(api_key):
        return "Error: Could not configure the AI model."
    try:
        pdf_reader = pypdf.PdfReader(BytesIO(pdf_file_bytes))
        all_findings_lines = []
        chunk_size = 10
        for i in range(0, len(pdf_reader.pages), chunk_size):
            chunk_text = "".join(page.extract_text() + "\n" for page in pdf_reader.pages[i:i+chunk_size])
            if chunk_text:
                prompt = f"{EXTRACTION_PROMPT}\n\n{chunk_text}"
                response = genai_model.generate_content(prompt)
                all_findings_lines.extend(line.strip() for line in response.text.splitlines() if '|' in line)
                time.sleep(3)
        if not all_findings_lines: return "No vulnerability findings could be extracted."
        if len(all_findings_lines) > 50:
            markdown_output = "### Detailed Vulnerability Findings (Large Report)\n| CVE ID | CVSS | Description | Solution |\n|---|---|---|---|\n"
            markdown_output += "\n".join(f"| {line.replace('|', ' | ')} |" for line in all_findings_lines)
            return markdown_output
        else:
            final_prompt = f"{SUMMARY_PROMPT}\n\n--- Extracted Findings ---\n" + "\n".join(all_findings_lines)
            summary_response = genai_model.generate_content(final_prompt)
            return f"### Executive Summary (Generated by Gemini AI)\n{summary_response.text}"
    except Exception as e:
        return f"An error occurred during Gemini PDF processing: {e}"

# --- Helper Functions ---
def find_cve_id(text):
    cve_pattern = re.compile(r'CVE[-‑\s]+\d{4}[-‑\s]+\d{4,7}', re.IGNORECASE)
    match = cve_pattern.search(text)
    if match:
        return "CVE-" + "-".join(re.findall(r'\d+', match.group(0)))
    return None

# --- CHATBOT HANDLERS ---
def handle_general_chat(query, api_key):
    if not genai_model and not configure_gemini(api_key):
        return "Error: Could not configure the AI model."
    return genai_model.generate_content(f"Answer this general question: {query}").text

def handle_nvd_query(query, api_key):
    if not genai_model and not configure_gemini(api_key):
        return "Error: Could not configure the AI model."
    cve_id = find_cve_id(query)
    if not cve_id:
        return "Please provide a valid CVE ID (e.g., CVE-2021-44228)."
    try:
        response = requests.get(f"{NVD_API_URL}?cveId={cve_id}")
        response.raise_for_status()
        context = {"nvd_data": response.json()}
        prompt = f"Precisely extract the information requested by the user '{query}' from the following JSON context: ```json {context} ```"
        return genai_model.generate_content(prompt).text
    except requests.exceptions.RequestException as e:
        return f"API request error: {e}"

# --- **UPDATED** Exploit-DB Handlers for Deployment ---
def find_exploit_for_cve(cve_id):
    if not cve_id: return None
    try:
        api_url = f"https://security-db.io/api/v1/search?q=cve:{cve_id}"
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        if data and isinstance(data, list) and len(data) > 0:
            return [{"title": ex.get("title"), "url": ex.get("url")} for ex in data[:3]]
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error querying Exploit-DB API: {e}")
        return None

def handle_exploit_query(query, api_key):
    cve_id = find_cve_id(query)
    if not cve_id:
        return "Please provide a valid CVE ID (e.g., CVE-2016-5195)."
    exploit_data = find_exploit_for_cve(cve_id)
    if not exploit_data:
        return f"No public exploits found for **{cve_id}** in the public Exploit-DB API."
    response_lines = [f"**Public exploits found for {cve_id}:**\n"]
    for i, exploit in enumerate(exploit_data):
        response_lines.append(f"---\n**Exploit {i+1}: {exploit['title']}**\n")
        response_lines.append(f"View details and code here:\n{exploit['url']}")
    response_lines.append("\n---\n\n**Disclaimer:** For educational/authorized testing only.")
    return "\n".join(response_lines)
