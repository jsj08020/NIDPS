from scapy.all import sniff, IP, TCP, ICMP
import datetime
from collections import defaultdict

LOG_FILE = "ids_log.txt"
packet_count = defaultdict(int)

def log_event(event_type, src, dst):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    log_text = f"[{now}] {event_type} 탐지 - {src} → {dst}"
    print(log_text)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_text + "\n")

def analyze_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in [21, 22, 23]:
                log_event(f"⚠️ 비정상 접근 (Port {dport})", src, dst)

        if packet.haslayer(ICMP):
            log_event("📡 Ping 요청", src, dst)

        packet_count[src] += 1
        if packet_count[src] > 50:
            log_event("🚨 트래픽 과다 발생", src, dst)
            packet_count[src] = 0

print("🔍 IDS 실행 중... 탐지 결과는 ids_log.txt에 저장됩니다.\n")

try:
    sniff(prn=analyze_packet, store=False)
except KeyboardInterrupt:
    print("\n🛑 IDS 종료됨.")
