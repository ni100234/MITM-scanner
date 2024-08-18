import socket
import ssl
import subprocess
from log import log  # Assuming log module for logging

def verify_endpoints(update_output):
    results = []  # Store results to save to file later

    def check_device(ip):
        try:
            # Check reachability using ping
            response = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE)
            if response.returncode == 0:
                message = f"{ip} is reachable."
                update_output(message)
                log(message)
                return True
            else:
                message = f"{ip} is not reachable."
                update_output(message)
                log(message)
                return False
        except subprocess.CalledProcessError:
            message = f"Error pinging {ip}."
            update_output(message)
            log(message)
            return False

    def verify_tls_cert(hostname):
        nonlocal results  # Access results variable from outer scope
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        message = f"TLS certificate for {hostname}: {cert}"
                        update_output(message)
                        log(message)
                        results.append(message)  # Append result to list
                    else:
                        message = f"No TLS certificate found for {hostname}"
                        update_output(message)
                        log(message)
                        results.append(message)  # Append result to list

        except ssl.SSLError as e:
            message = f"SSL error: {e}"
            update_output(message)
            log(message)
            results.append(message)  # Append result to list
        except Exception as e:
            message = f"Error verifying TLS certificate for {hostname}: {e}"
            update_output(message)
            log(message)
            results.append(message)  # Append result to list

    # Define IPs to verify
    ips = ["192.168.133.137"]

    for ip in ips:
        if check_device(ip):
            # Perform SSL/TLS certificate verification for HTTPS endpoints
            verify_tls_cert(ip)

    # Save results to file
    save_results(results)

def save_results(results):
    filename = "last_scan/endpoint_verification.txt"
    with open(filename, "w") as file:
        for result in results:
            file.write(result + "\n")

if __name__ == "__main__":
    def print_output(message):
        print(message)
    
    # Call verify_endpoints with print_output for testing
    verify_endpoints(print_output)
