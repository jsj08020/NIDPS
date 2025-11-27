from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime
import time
from collections import defaultdict, deque
import os

# ============================
#  설정 / 탐지 기준 상수
# ============================

# 시간 기준 (초)
TIME_WINDOW_DDOS = 10           # DDoS / Flood 계열 판단용 창
TIME_WINDOW_PORT_SCAN = 10      # 포트 스캔 판단용 창
TIME_WINDOW_BRUTE_FORCE = 30    # 무차별 대입 판단용 창

# 임계값
DDOS_PACKET_THRESHOLD = 80      # 10초 내 전체 패킷 수
SYN_FLOOD_THRESHOLD = 50        # 10초 내 SYN 패킷 수
UDP_FLOOD_THRESHOLD = 50        # 10초 내 UDP 패킷 수
ICMP_FLOOD_THRESHOLD = 50       # 10초 내 ICMP 패킷 수
PORT_SCAN_PORT_THRESHOLD = 10   # 10초 내 서로 다른 포트 수
BRUTE_FORCE_ATTEMPT_THRESHOLD = 10  # 30초 내 로그인 관련 포트 접속 시도 수

# 포트 기준
BRUTE_FORCE_PORTS = [21, 22, 23, 3389, 445]  # FTP/SSH/Telnet/RDP/SMB 등
SUSPICIOUS_PORTS = [21, 22, 23]              # 단일 비정상 접근 포트 표시용 (원래 쓰던 기준 유지)

# SQL 인젝션 패턴 (단순 시그니처 기반)
SQLI_PATTERNS = [
    " or 1=1",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    " union select ",
    " sleep(",
    " benchmark(",
    "/*",
    "--",
    " or 'a'='a",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "ids_log.txt")


# ============================
#  상태 저장용 자료구조
# ============================

# DDoS / Flood 감지용: IP별 최근 패킷 시간
all_packet_times = defaultdict(lambda: deque())

# SYN / UDP / ICMP 개별 Flood 감지용
syn_times = defaultdict(lambda: deque())
udp_times = defaultdict(lambda: deque())
icmp_times = defaultdict(lambda: deque())

# 포트 스캔 감지용: (시간, dport) 기록
port_scan_records = defaultdict(lambda: deque())

# 브루트포스(무차별 대입) 감지용: 로그인 관련 포트 접속 시도 시간
brute_force_times = defaultdict(lambda: deque())


# ============================
#  공통 유틸 함수
# ============================

def prune_old(deq: deque, now_ts: float, window: int):
    """window(초)보다 오래된 기록 제거"""
    while deq and now_ts - deq[0] > window:
        deq.popleft()


def log_event(event_type: str, src: str, dst: str, severity: str = "정보"):
    """
    severity: "심각" / "높음" / "중간" / "낮음" / "정보"
    로그 포맷: [HH:MM:SS] [심각도] 메시지 - src → dst
    """
    now = datetime.datetime.now().strftime("%H:%M:%S")
    text = f"[{now}] [{severity}] {event_type} - {src} → {dst}"
    print(text)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")


# ============================
#  메인 패킷 분석 함수
# ============================

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    now_ts = time.time()

    # --------------------------------
    # 1. 공통 패킷 수 기반 (DDoS / Flood)
    # --------------------------------
    all_packet_times[src].append(now_ts)
    prune_old(all_packet_times[src], now_ts, TIME_WINDOW_DDOS)

    if len(all_packet_times[src]) >= DDOS_PACKET_THRESHOLD:
        log_event("🚨 DDoS 의심: 트래픽 과다 발생", src, dst, severity="심각")
        all_packet_times[src].clear()

    # --------------------------------
    # 2. TCP 관련 (SYN Flood, Port Scan, Brute Force)
    # --------------------------------
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        dport = tcp.dport
        flags = tcp.flags

        # (1) SYN Flood 감지: SYN 플래그 패킷이 짧은 시간에 너무 많이 들어오는 경우
        if flags == "S":
            syn_times[src].append(now_ts)
            prune_old(syn_times[src], now_ts, TIME_WINDOW_DDOS)

            if len(syn_times[src]) >= SYN_FLOOD_THRESHOLD:
                log_event("🚨 SYN Flood 의심", src, dst, severity="심각")
                syn_times[src].clear()

        # (2) 포트 스캔 감지: 짧은 시간 내 서로 다른 포트에 여러 번 접근
        port_scan_records[src].append((now_ts, dport))
        # 오래된 기록 제거
        while port_scan_records[src] and now_ts - port_scan_records[src][0][0] > TIME_WINDOW_PORT_SCAN:
            port_scan_records[src].popleft()

        unique_ports = {p for (_, p) in port_scan_records[src]}
        if len(unique_ports) >= PORT_SCAN_PORT_THRESHOLD:
            log_event(f"⚠️ 포트 스캔 의심 (최근 {TIME_WINDOW_PORT_SCAN}초 내 {len(unique_ports)}개 포트 접근)", src, dst, severity="높음")
            port_scan_records[src].clear()

        # (3) 단일 비정상 포트 접근 (원래 기준 유지)
        if dport in SUSPICIOUS_PORTS:
            log_event(f"⚠️ 비정상 Port 접근({dport})", src, dst, severity="중간")

        # (4) 브루트포스(무차별 대입) 감지: SSH/FTP/Telnet/RDP 같은 포트에 반복 접속 시도
        if dport in BRUTE_FORCE_PORTS:
            brute_force_times[src].append(now_ts)
            prune_old(brute_force_times[src], now_ts, TIME_WINDOW_BRUTE_FORCE)

            if len(brute_force_times[src]) >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
                log_event(f"🚨 무차별 대입(Brute Force) 시도 의심 (포트 {dport})", src, dst, severity="높음")
                brute_force_times[src].clear()

    # --------------------------------
    # 3. UDP Flood 감지
    # --------------------------------
    if packet.haslayer(UDP):
        udp_times[src].append(now_ts)
        prune_old(udp_times[src], now_ts, TIME_WINDOW_DDOS)

        if len(udp_times[src]) >= UDP_FLOOD_THRESHOLD:
            log_event("🚨 UDP Flood 의심", src, dst, severity="심각")
            udp_times[src].clear()

    # --------------------------------
    # 4. ICMP(Ping) – Ping Flood + 단순 Ping 로그
    # --------------------------------
    if packet.haslayer(ICMP):
        # 단순 Ping 요청 로그 (낮음)
        log_event("📡 Ping 요청", src, dst, severity="낮음")

        icmp_times[src].append(now_ts)
        prune_old(icmp_times[src], now_ts, TIME_WINDOW_DDOS)

        if len(icmp_times[src]) >= ICMP_FLOOD_THRESHOLD:
            log_event("⚠️ Ping Flood 의심", src, dst, severity="높음")
            icmp_times[src].clear()

    # --------------------------------
    # 5. SQL Injection 시도 감지 (HTTP Payload 기반)
    # --------------------------------
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore").lower()
        except Exception:
            payload = ""

        if payload:
            if any(pattern in payload for pattern in SQLI_PATTERNS):
                log_event("🚨 SQL 인젝션 시도 의심", src, dst, severity="높음")


# ============================
#  메인 실행부
# ============================

if __name__ == "__main__":
    print("🔍 IDS 실행 중... (ids_log.txt에 탐지 로그 기록)")
    print(" - 공격 유형: 포트 스캔 / SYN Flood / UDP Flood / Ping Flood / 무차별 대입 / SQL 인젝션 / DDoS")
    print(f" - DDoS 기준: {TIME_WINDOW_DDOS}초 내 {DDOS_PACKET_THRESHOLD}개 이상 패킷")
    print(f" - SYN Flood 기준: {TIME_WINDOW_DDOS}초 내 SYN {SYN_FLOOD_THRESHOLD}개 이상")
    print(f" - UDP Flood 기준: {TIME_WINDOW_DDOS}초 내 UDP {UDP_FLOOD_THRESHOLD}개 이상")
    print(f" - Ping Flood 기준: {TIME_WINDOW_DDOS}초 내 ICMP {ICMP_FLOOD_THRESHOLD}개 이상")
    print(f" - 포트 스캔 기준: {TIME_WINDOW_PORT_SCAN}초 내 서로 다른 포트 {PORT_SCAN_PORT_THRESHOLD}개 이상")
    print(f" - 무차별 대입 기준: {TIME_WINDOW_BRUTE_FORCE}초 내 로그인 포트 접속 {BRUTE_FORCE_ATTEMPT_THRESHOLD}회 이상\n")

    try:
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("🛑 IDS 종료됨")
