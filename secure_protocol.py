import requests
import ssl
import socket
from log import log  # Assuming log module for logging

def enforce_secure_protocols(update_output):
    def check_https(url):
        try:
            response = requests.get(url, verify=True)
            if response.status_code == 200:
                message = f"{url} is using HTTPS."
                update_output(message)
                log(message)
            else:
                message = f"{url} is not using HTTPS (Status Code: {response.status_code})."
                update_output(message)
                log(message)
        except requests.exceptions.SSLError:
            message = f"{url} is not using HTTPS (SSL Error)."
            update_output(message)
            log(message)
        except requests.exceptions.RequestException as e:
            message = f"Error accessing {url}: {e}"
            update_output(message)
            log(message)

    urls = ["https://192.168.133.135"]
    for url in urls:
        check_https(url)

def verify_tls_cert(hostname, update_output):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        message = f"TLS certificate for {hostname}: {cert}"
        update_output(message)
        log(message)
    except Exception as e:
        message = f"Error verifying TLS certificate for {hostname}: {e}"
        update_output(message)
        log(message)

    finally:
        conn.close()

if __name__ == "__main__":
    def print_output(message):
        print(message)
    
    # Call enforce_secure_protocols and verify_tls_cert once
    enforce_secure_protocols(print_output)
    verify_tls_cert("192.168.133.135", print_output)

    # Save results to last_scan/secure_protocol.txt
    with open("last_scan/secure_protocol.txt", "w") as file:

        
        def update_and_write_output(message):
            file.write(message + "\n")
        
        enforce_secure_protocols(update_and_write_output)
        verify_tls_cert("192.168.133.135", update_and_write_output)
