from scapy.all import sniff, IP, TCP, ICMP
import datetime
from collections import defaultdict
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "ids_log.txt")

packet_count = defaultdict(int)

def log_event(event_type, src, dst):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    text = f"[{now}] {event_type} - {src} → {dst}"
    print(text)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def analyze_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        # 비정상 포트 접근
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in [21, 22, 23]:
                log_event(f"⚠️ 비정상 Port 접근({dport})", src, dst)

        # Ping 탐지
        if packet.haslayer(ICMP):
            log_event("📡 Ping 요청", src, dst)

        # 트래픽 과다
        packet_count[src] += 1
        if packet_count[src] > 50:
            log_event("🚨 트래픽 과다 발생", src, dst)
            packet_count[src] = 0

print("🔍 IDS 실행 중... (ids_log.txt 기록)")

try:
    sniff(prn=analyze_packet, store=False)
except KeyboardInterrupt:
    print("🛑 IDS 종료됨")
