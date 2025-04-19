import nmap
import requests
import sys
from version import __version__

print(f"Current version: {__version__}")

# NVD API endpoint
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def scan_target(target, ports):
 
    scanner = nmap.PortScanner()

    # Decide what ports to scan
    if ports == "top1000":
        scan_args = "--top-ports 1000 -sV"
    else:
        scan_args = f"-p {ports} -sV"

    print(f"Scanning {target} with arguments: {scan_args}\n")
    
    # Run the Nmap scan
    scanner.scan(target, arguments=scan_args)

    
    vulnerabilities = {}

    # Iterate over discovered hosts
    for host in scanner.all_hosts():
        print(f"[+] Host: {host} ({scanner[host].hostname()})")

        # Only check TCP ports here
        if 'tcp' not in scanner[host]:
            continue

        for port, info in scanner[host]['tcp'].items():
            service = info['name']
            product = info.get('product', 'Unknown')
            version = info.get('version', 'Unknown')
            state = info['state']

            print(f"  Port {port}: {service} ({state}) - {product} {version}")

            # If product/version is identified, search for CVEs in NVD
            if product != "Unknown" and version != "Unknown":
                cve_list = check_cve_in_nvd(product, version)
                if cve_list:
                    key = f"{product} {version}"
                    vulnerabilities.setdefault(key, [])
                    vulnerabilities[key].extend(cve_list)

    
    if vulnerabilities:
        print("\n Found Vulnerabilities with possible Exploit References")
        for software, cve_data in vulnerabilities.items():
            print(f"\n[Software: {software}]")
            for cve_id, references in cve_data:
                print(f" - CVE: {cve_id}")
                if references:
                    print("   References:")
                    for ref in references:
                        print(f" {ref}")
                else:
                    print(" (No references provided by NVD)")
    else:
        print("\nNo known vulnerabilities found for detected services.")

def check_cve_in_nvd(product, version):
   
    query = f"{product} {version}"
    url = f"{NVD_API}?keywordSearch={query}"
    cve_results = []

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            # NVD 2.0 returns a 'vulnerabilities' list
            vulnerabilities = data.get('vulnerabilities', [])
            for item in vulnerabilities:
                cve_id = item['cve']['id']
                # references is a list of objects with "url" key
                refs = item['cve'].get('references', [])
                ref_urls = [r['url'] for r in refs if 'url' in r]

                cve_results.append((cve_id, ref_urls))
        else:
            print(f"[ERROR] NVD API returned status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Could not reach NVD: {e}")

    # Return up to 5 results
    return cve_results[:5]

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    scan_ports = input("Enter ports to scan (e.g., '22,80,443' or 'top1000'): ")
    scan_target(target_ip, scan_ports)