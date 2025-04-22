import tkinter as tk
from tkinter import messagebox
from functools import partial
from threading import Thread
import nmap
import requests
import csv
import os
from datetime import datetime
from version import __version__

#Checks if there is a directory for vulnerability results if not it creates one
if not os.path.exists('VulnerabilityResults'):
    os.makedirs("VulnerabilityResults")

# CSV filename and headers
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
csv_filename = f"VulnerabilityResults/shadow_scan_report_{timestamp}.csv"
headers = ['Vulnerability ID', 'Description', 'Severity', 'CVSS Score']

# Assign severity level based on CVSS score
def assign_severity(score, version):
    if score == "N/A":
        return "Unknown"
    score = float(score)
    if version == "v3":
        if score >= 9.0: return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score > 0.0: return "Low"
        else: return "None"
    elif version == "v2":
        if score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        else: return "Low"
    return "Unknown"

# Performs the scan
def execute_scan(target, ports, output_text):
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)  
    output_text.insert(tk.END, f"Current version: {__version__}\n\n")

    try:
        scan_target(target, ports, output_text)
    except Exception as e:
        output_text.insert(tk.END, f"\nError: {str(e)}\n")
    
    output_text.config(state=tk.DISABLED)

# Scan a given target with Nmap
def scan_target(target, ports, output_text):
    scanner = nmap.PortScanner()
    scan_args = "--top-ports 1000 -sV" if ports == "top1000" else f"-p {ports} -sV"
    output_text.insert(tk.END, f"Scanning {target} with arguments: {scan_args}\n\n")
    scanner.scan(target, arguments=scan_args)

    vulnerabilities = {}

    for host in scanner.all_hosts():
        output_text.insert(tk.END, f"[+] Host: {host} ({scanner[host].hostname()})\n")

        if 'tcp' not in scanner[host]:
            continue

        for port, info in scanner[host]['tcp'].items():
            service = info['name']
            product = info.get('product', 'Unknown')
            version = info.get('version', 'Unknown')
            state = info['state']
            output_text.insert(tk.END, f"  Port {port}: {service} ({state}) - {product} {version}\n")

            if product != "Unknown" and version != "Unknown":
                cve_list = check_cve_in_nvd(product, version)
                if cve_list:
                    key = f"{product} {version}"
                    vulnerabilities.setdefault(key, [])
                    vulnerabilities[key].extend(cve_list)

    if vulnerabilities:
        output_text.insert(tk.END, "\nFound Vulnerabilities:\n")

        with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()

            for software, cve_data in vulnerabilities.items():
                output_text.insert(tk.END, f"\n[Software: {software}]\n")
                for cve_id, cvss_score, severity, references in cve_data:
                    output_text.insert(tk.END, f" - CVE: {cve_id} | Severity: {severity} (CVSS: {cvss_score})\n")
                    writer.writerow({
                        'Vulnerability ID': cve_id,
                        'Description': software,
                        'Severity': severity,
                        'CVSS Score': cvss_score
                    })

                    if references:
                        output_text.insert(tk.END, "   References:\n")
                        for ref in references:
                            output_text.insert(tk.END, f"     {ref}\n")
                    else:
                        output_text.insert(tk.END, "   (No references provided by NVD)\n")
        output_text.insert(tk.END, f"\nResults saved to: {csv_filename}\n")
    else:
        output_text.insert(tk.END, "\nNo known vulnerabilities found for detected services.\n")

# Query NVD for CVEs
def check_cve_in_nvd(product, version):
    query = f"{product} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"

    cve_results = []

    try:
        print(f"Querying NVD with: {query}")
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            for item in vulnerabilities:
                cve_id = item['cve']['id']
                cvss_score = "N/A"
                severity = "Unknown"
                metrics = item['cve'].get('metrics', {})

                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data['baseScore']
                    severity = assign_severity(cvss_score, "v3")
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data['baseScore']
                    severity = assign_severity(cvss_score, "v3")
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data['baseScore']
                    severity = assign_severity(cvss_score, "v2")

                refs = item['cve'].get('references', [])
                ref_urls = [r['url'] for r in refs if 'url' in r]

                cve_results.append((cve_id, cvss_score, severity, ref_urls))
        else:
            print(f"[ERROR] NVD API returned status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Could not reach NVD: {e}")

    return cve_results

# GUI Setup
def create_gui():
    window = tk.Tk()
    window.title("Shadow Scanner")

    tk.Label(window, text="Enter target IP:").pack()
    target_entry = tk.Entry(window)
    target_entry.pack()

    tk.Label(window, text="Enter ports to scan (e.g., '22,80,443' or 'top1000'):").pack()
    ports_entry = tk.Entry(window)
    ports_entry.pack()

    output_text = tk.Text(window, height=20, width=80)
    output_text.pack()

    scan_button = tk.Button(window, text="Scan", command=partial(scan_clicked, target_entry, ports_entry, output_text))
    scan_button.pack()

    window.mainloop()

# Handle scan button click
def scan_clicked(target_entry, ports_entry, output_text):
    target = target_entry.get()
    ports = ports_entry.get()
    if target and ports:
        Thread(target=execute_scan, args=(target, ports, output_text)).start()
    else:
        messagebox.showerror("Error", "Please enter both target IP and ports.")

if __name__ == "__main__":
    create_gui()
