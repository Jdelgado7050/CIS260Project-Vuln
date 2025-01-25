#This is the start of creating a vulnerability scanner
import nmap 
#test nmap functionality #print(nmap.__version__) 

def scan_target(target, ports):
    scanner = nmap.PortScanner()
    print("Scanning ports on {target} to see if any are open")

    scanner.scan(target, arguments= f" -p {ports} -sV" )

    for host in scanner.all_hosts():
        print("n[+] Host: {host} ({scanner[host].hostname()})")
        for port, info in scanner[host]['tcp'].items():
            print(f"Port {port}: {info['name']} ({info['state']}) - {info['product']} {info['version']}")
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    scan_ports = input("Enter ports to scan (recommended ports: 80, 443, & 22): ")
    scan_target(target_ip, scan_ports)