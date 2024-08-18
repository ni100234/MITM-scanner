import nmap
from datetime import datetime
from log import log

def scan_network(output_callback):
    log("Network scan started.")
    start_time = datetime.now()

    # Initialize Nmap scanner with custom command
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.133.135', arguments='-sTU --top-ports 1000')  # Scan top 1000 TCP and UDP ports

    scan_results = ""
    open_ports_found = False

    for host in nm.all_hosts():
        scan_results += f"Host: {host}\n\n"
        for proto in nm[host].all_protocols():
            scan_results += f"Protocol: {proto}\n"
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                scan_results += f"Port: {port}\tState: {nm[host][proto][port]['state']}\n"
                scan_results += f"Service: {nm[host][proto][port]['name']}\n"
                if 'info' in nm[host][proto][port]:
                    scan_results += f"Service Info: {nm[host][proto][port]['info']}\n"
                scan_results += "\n"
                open_ports_found = True  # Set flag if any open port is found

        # Update GUI output incrementally for each host
        output_callback(scan_results)

    log("Network scan completed.")
    log(f"Scan duration: {datetime.now() - start_time}")

    if not open_ports_found:
        # No open ports found message
        output_callback("No open ports were found.")

    return scan_results if open_ports_found else "No open ports were found."

if __name__ == "__main__":
    def print_output(output):
        print(output)

    scan_network(print_output)
