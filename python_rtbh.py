from scapy.all import sniff, IP
import paramiko
import logging
import time
from ipaddress import ip_network, ip_address
import os

TRIGGER_ROUTER_IP = "192.168.138.153"
TRIGGER_ROUTER_USERNAME = "aspu1"
TRIGGER_ROUTER_PASSWORD = "cisco1"

TRAFFIC_THRESHOLD = 5  

TOPOLOGY_SUBNETS = [
    "192.168.138.153/32",
    "192.168.10.0/24",
    "192.168.20.0/24",
    "192.168.30.0/24",
    "192.168.1.0/24",
]

INTERFACE = "eth0"  

logging.basicConfig(filename="rtbh_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

traffic_count = {}

def apply_rtbh(malicious_ip):
    logging.info(f"Applying RTBH for malicious IP: {malicious_ip}")
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(TRIGGER_ROUTER_IP, username=TRIGGER_ROUTER_USERNAME, password=TRIGGER_ROUTER_PASSWORD)
        shell = ssh_client.invoke_shell()
        time.sleep(1)
        shell.recv(1024)

        commands = [
            "enable",
            "configure terminal",
            f"ip route {malicious_ip} 255.255.255.255 Null0",
            "exit",
            "write memory"
        ]
        
        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(1)
            output = shell.recv(1024).decode('utf-8')
            logging.info(f"Command output: {output.strip()}")

        logging.info(f"RTBH successfully applied for {malicious_ip}")
    except Exception as e:
        logging.error(f"Failed to apply RTBH for {malicious_ip}: {e}")
    finally:
        ssh_client.close()

def detect_malicious(ip):
    return traffic_count.get(ip, 0) > TRAFFIC_THRESHOLD

def analyze_traffic(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        print(f"Packet detected: {src_ip} → {dst_ip}")  

        if any(ip_address(dst_ip) in ip_network(subnet) for subnet in TOPOLOGY_SUBNETS):
            traffic_count[src_ip] = traffic_count.get(src_ip, 0) + 1
            print(f"Traffic count for {src_ip}: {traffic_count[src_ip]}") 

            if detect_malicious(src_ip):
                print(f"[ALERT] Detected malicious IP: {src_ip}. Applying RTBH.")
                apply_rtbh(src_ip)

def monitor_traffic():
    print("Starting traffic monitoring...")  
    sniff(filter="ip", prn=analyze_traffic, store=0, timeout=30)

if __name__ == "__main__":
    try:
        print("RTBH monitoring is active. Press Ctrl+C to stop.")
        while True:
            monitor_traffic()
            traffic_count.clear()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Exiting RTBH monitoring...")
        print("RTBH monitoring stopped.")
