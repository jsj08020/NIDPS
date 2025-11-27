from scapy.all import sniff, IP, TCP, ICMP
import datetime
from collections import defaultdict, deque
import time
import os

# === 분석 기준 (튜닝 가능) ===
SUSPICIOUS_PORTS = [21, 22, 23]  # 비정상 접근으로 보는 포트
TRAFFIC_WINDOW_SEC = 10          # 트래픽 과다 판단 시간 창(초)
TRAFFIC_THRESHOLD = 50           # 창 내 패킷 개수 기준
PING_THRESHOLD = 5               # 한 IP에서 연속으로 발생하는 Ping 기준

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "ids_log.txt")

# 출발지 IP별 최근 패킷 시간 기록용
packet_times = defaultdict(lambda: deque())
# 출발지 IP별 연속 Ping 카운트
ping_count = defaultdict(int)


def log_event(event_type: str, src: str, dst: str, severity: str = "정보"):
    """
    severity: 심각 / 높음 / 중간 / 낮음 / 정보
    """
    now = datetime.datetime.now().strftime("%H:%M:%S")
    log_text = f"[{now}] [{severity}] {event_type} - {src} → {dst}"
    print(log_text)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_text + "\n")


def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    now_ts = time.time()

    # --- 공통: 최근 패킷 시간 기록 (트래픽 과다 분석용) ---
    packet_times[src].append(now_ts)

    # TRAFFIC_WINDOW_SEC 보다 오래된 패킷은 제거
    while packet_times[src] and now_ts - packet_times[src][0] > TRAFFIC_WINDOW_SEC:
        packet_times[src].popleft()

    # 현재 시간창 내 패킷 수가 기준 이상이면 트래픽 과다 (심각)
    if len(packet_times[src]) >= TRAFFIC_THRESHOLD:
        log_event("🚨 트래픽 과다 발생", src, dst, severity="심각")
        packet_times[src].clear()  # 한 번 경고 후 리셋

    # --- 포트 스캔 / 비정상 포트 접근 (중간) ---
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        if dport in SUSPICIOUS_PORTS:
            log_event(f"⚠️ 비정상 Port 접근({dport})", src, dst, severity="중간")

    # --- Ping(ICMP) 분석 ---
    if packet.haslayer(ICMP):
        # Ping 요청은 낮음
        log_event("📡 Ping 요청", src, dst, severity="낮음")

        ping_count[src] += 1

        # 연속 Ping 횟수가 기준 이상이면 Ping 과다 발생 (높음)
        if ping_count[src] >= PING_THRESHOLD:
            log_event("⚠️ Ping 과다 발생", src, dst, severity="높음")
            ping_count[src] = 0  # 카운트 리셋
    else:
        # ICMP가 아닌 다른 패킷이 오면 연속 Ping은 끊긴 것으로 보고 초기화
        ping_count[src] = 0


print("🔍 IDS 실행 중... (ids_log.txt에 탐지 로그 기록)")
print(f" - 비정상 포트 기준: {SUSPICIOUS_PORTS}")
print(f" - 트래픽 과다 기준: {TRAFFIC_WINDOW_SEC}초 내 {TRAFFIC_THRESHOLD}개 이상")
print(f" - Ping 과다 기준: 연속 {PING_THRESHOLD}회 이상")
print(f" - 심각도: 심각 / 높음 / 중간 / 낮음\n")

try:
    sniff(prn=analyze_packet, store=False)
except KeyboardInterrupt:
    print("🛑 IDS 종료됨")
