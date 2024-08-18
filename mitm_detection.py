import scapy.all as scapy
import threading
import time
import os
from log import log  # Assuming log module for logging

def detect_mitm(update_output):
    suspicious_packets = set()

    def get_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None

    def sniff_packets(interface, duration):
        stop_sniffing = threading.Event()

        def stop_sniff():
            time.sleep(duration)
            stop_sniffing.set()

        def process_sniffed_packet(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                try:
                    real_mac = get_mac(packet[scapy.ARP].psrc)
                    response_mac = packet[scapy.ARP].hwsrc
                    if real_mac and real_mac != response_mac:
                        message = f"[!] Possible MITM attack detected! Real MAC: {real_mac}, Fake MAC: {response_mac}"
                        if (real_mac, response_mac) not in suspicious_packets:
                            suspicious_packets.add((real_mac, response_mac))
                            update_output(message)
                except IndexError:
                    pass

        log("Starting MITM detection...")
        sniff_thread = threading.Thread(target=scapy.sniff, kwargs={
            'iface': interface, 'store': False, 'prn': process_sniffed_packet, 'stop_filter': lambda x: stop_sniffing.is_set()})
        sniff_thread.start()
        stop_thread = threading.Thread(target=stop_sniff)
        stop_thread.start()

        stop_thread.join(timeout=duration)
        stop_sniffing.set()  # Ensure sniffing stops even if stop_thread.join() times out

        sniff_thread.join()

    sniff_packets("eth0", 30)  # Run sniffing for 30 seconds

    if not suspicious_packets:
        message = "No MITM attacks were detected."
        update_output(message)
        suspicious_packets.add(("No MITM attacks were detected.",))

    # Specify the file path to save inside the last_scan folder
    file_path = os.path.join("last_scan", "mitm_detection.txt")
    
    # Save results to mitm_detection.txt inside last_scan folder
    with open(file_path, "w") as file:
        for real_mac, fake_mac in suspicious_packets:
            if real_mac == "No MITM attacks were detected.":
                file.write(f"{real_mac}\n")
            else:
                file.write(f"[!] Possible MITM attack detected! Real MAC: {real_mac}, Fake MAC: {fake_mac}\n")

    log("MITM detection completed.")

# Test function (can be removed in production)
if __name__ == "__main__":
    def print_output(message):
        print(message)
    
    detect_mitm(print_output)
