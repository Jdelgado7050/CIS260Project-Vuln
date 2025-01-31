#This is the start of creating a vuln scanner
import nmap
import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def scan_target(target, ports):
    
    scanner = nmap.PortScanner()

    # Decide what ports to scan, top 1000 common ports added for user convenience
    if ports == "top1000":
        scan_args = "--top-ports 1000 -sV"
    else:
        scan_args = f"-p {ports} -sV"

    print(f"Scanning {target} with arguments: {scan_args}\n")
    
    # Run the Nmap scan
    scanner.scan(target, arguments=scan_args)

    #Stores vulnerabilities
    vulnerabilities = {}

    
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
    #Next step is to complete full nvd api integration and possible UDP port scan
