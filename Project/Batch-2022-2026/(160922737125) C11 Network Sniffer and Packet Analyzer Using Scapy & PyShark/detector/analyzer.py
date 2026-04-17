import os
import json
from collections import Counter

try:
    from scapy.all import rdpcap
except Exception:
    rdpcap = None

try:
    import pyshark
except Exception:
    pyshark = None


SUSPICIOUS_PORTS = {21, 23, 445, 3389, 1433, 3306, 5900}
SUSPICIOUS_KEYWORDS = [
    "malware", "trojan", "exploit", "command and control", "suspicious",
    "unauthorized", "failed login", "bruteforce", "port scan", "ddos",
    "syn flood", "attack", "exfiltration", "powershell", "payload"
]


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def risk_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def analyze_text(text_input: str) -> dict:
    lowered = text_input.lower()
    findings = []
    score = 0

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    for kw in keyword_hits:
        findings.append({
            "type": "Keyword Match",
            "severity": "Medium",
            "details": f"Suspicious term detected: '{kw}'"
        })
        score += 8

    tcp_mentions = lowered.count("tcp")
    udp_mentions = lowered.count("udp")
    icmp_mentions = lowered.count("icmp")
    port_mentions = sum(lowered.count(str(port)) for port in SUSPICIOUS_PORTS)

    if tcp_mentions > 10:
        findings.append({
            "type": "Protocol Observation",
            "severity": "Low",
            "details": "Heavy TCP presence observed in manual input."
        })
        score += 10

    if udp_mentions > 10:
        findings.append({
            "type": "Protocol Observation",
            "severity": "Low",
            "details": "Heavy UDP presence observed in manual input."
        })
        score += 8

    if icmp_mentions > 5:
        findings.append({
            "type": "Network Behavior",
            "severity": "Medium",
            "details": "Repeated ICMP activity may indicate probing or diagnostics."
        })
        score += 12

    if port_mentions > 0:
        findings.append({
            "type": "Port Reference",
            "severity": "High",
            "details": "References to sensitive ports found in supplied text."
        })
        score += min(25, port_mentions * 5)

    packets_analyzed = max(1, len(text_input.splitlines()))
    risk_level = risk_from_score(score)
    summary = (
        f"Manual text analysis completed. {len(findings)} findings detected across "
        f"{packets_analyzed} text lines. Overall risk assessed as {risk_level}."
    )

    return {
        "summary": summary,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "packets_analyzed": packets_analyzed,
        "findings": findings
    }


def analyze_pcap_with_scapy(file_path: str) -> dict:
    findings = []
    score = 0
    packets_analyzed = 0

    if rdpcap is None:
        return {
            "summary": "Scapy is not available in this environment.",
            "risk_score": 0,
            "risk_level": "Low",
            "packets_analyzed": 0,
            "findings": [{
                "type": "Dependency",
                "severity": "Low",
                "details": "Scapy could not be imported."
            }]
        }

    packets = rdpcap(file_path)
    packets_analyzed = len(packets)

    protocol_counter = Counter()
    suspicious_port_hits = 0
    broadcast_hits = 0
    syn_only_hits = 0
    large_packet_hits = 0

    for pkt in packets:
        try:
            if pkt.haslayer("TCP"):
                protocol_counter["TCP"] += 1
                tcp_layer = pkt["TCP"]

                dport = safe_int(getattr(tcp_layer, "dport", 0))
                sport = safe_int(getattr(tcp_layer, "sport", 0))

                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    suspicious_port_hits += 1

                flags = str(getattr(tcp_layer, "flags", ""))
                if "S" in flags and "A" not in flags:
                    syn_only_hits += 1

            elif pkt.haslayer("UDP"):
                protocol_counter["UDP"] += 1
                udp_layer = pkt["UDP"]
                dport = safe_int(getattr(udp_layer, "dport", 0))
                sport = safe_int(getattr(udp_layer, "sport", 0))
                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    suspicious_port_hits += 1

            elif pkt.haslayer("ICMP"):
                protocol_counter["ICMP"] += 1
            else:
                protocol_counter["OTHER"] += 1

            if hasattr(pkt, "dst"):
                dst = str(getattr(pkt, "dst", ""))
                if dst.endswith("255"):
                    broadcast_hits += 1

            if len(pkt) > 1200:
                large_packet_hits += 1

        except Exception:
            continue

    if suspicious_port_hits > 0:
        findings.append({
            "type": "Sensitive Port Activity",
            "severity": "High",
            "details": f"Detected {suspicious_port_hits} packets involving sensitive ports."
        })
        score += min(35, suspicious_port_hits // 3 + 15)

    if syn_only_hits > 20:
        findings.append({
            "type": "Possible SYN Scan/Flood",
            "severity": "Critical" if syn_only_hits > 100 else "High",
            "details": f"Observed {syn_only_hits} SYN-only TCP packets."
        })
        score += 30 if syn_only_hits > 100 else 20

    if broadcast_hits > 15:
        findings.append({
            "type": "Broadcast Activity",
            "severity": "Medium",
            "details": f"Observed {broadcast_hits} broadcast destination packets."
        })
        score += 10

    if large_packet_hits > 10:
        findings.append({
            "type": "Large Packet Volume",
            "severity": "Medium",
            "details": f"Observed {large_packet_hits} unusually large packets."
        })
        score += 10

    findings.append({
        "type": "Protocol Breakdown",
        "severity": "Info",
        "details": f"TCP={protocol_counter.get('TCP', 0)}, UDP={protocol_counter.get('UDP', 0)}, "
                   f"ICMP={protocol_counter.get('ICMP', 0)}, OTHER={protocol_counter.get('OTHER', 0)}"
    })

    risk_level = risk_from_score(score)
    summary = (
        f"PCAP analysis via Scapy completed. {packets_analyzed} packets processed with "
        f"{len(findings)} findings. Overall risk assessed as {risk_level}."
    )

    return {
        "summary": summary,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "packets_analyzed": packets_analyzed,
        "findings": findings
    }


def analyze_pcap_with_pyshark(file_path: str) -> dict:
    findings = []
    score = 0
    packets_analyzed = 0

    if pyshark is None:
        return {
            "summary": "PyShark is not available in this environment.",
            "risk_score": 0,
            "risk_level": "Low",
            "packets_analyzed": 0,
            "findings": [{
                "type": "Dependency",
                "severity": "Low",
                "details": "PyShark could not be imported."
            }]
        }

    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    suspicious_port_hits = 0

    capture = pyshark.FileCapture(file_path, keep_packets=False)
    try:
        for pkt in capture:
            packets_analyzed += 1

            highest = getattr(pkt, "highest_layer", "OTHER")
            if highest == "TCP":
                tcp_count += 1
            elif highest == "UDP":
                udp_count += 1
            elif highest == "ICMP":
                icmp_count += 1

            if hasattr(pkt, "tcp"):
                srcport = safe_int(getattr(pkt.tcp, "srcport", 0))
                dstport = safe_int(getattr(pkt.tcp, "dstport", 0))
                if srcport in SUSPICIOUS_PORTS or dstport in SUSPICIOUS_PORTS:
                    suspicious_port_hits += 1

            if hasattr(pkt, "udp"):
                srcport = safe_int(getattr(pkt.udp, "srcport", 0))
                dstport = safe_int(getattr(pkt.udp, "dstport", 0))
                if srcport in SUSPICIOUS_PORTS or dstport in SUSPICIOUS_PORTS:
                    suspicious_port_hits += 1

    finally:
        capture.close()

    if suspicious_port_hits > 0:
        findings.append({
            "type": "Sensitive Port Activity",
            "severity": "High",
            "details": f"Detected {suspicious_port_hits} packets involving sensitive ports."
        })
        score += min(35, suspicious_port_hits // 2 + 15)

    findings.append({
        "type": "Protocol Breakdown",
        "severity": "Info",
        "details": f"TCP={tcp_count}, UDP={udp_count}, ICMP={icmp_count}"
    })

    if icmp_count > 20:
        findings.append({
            "type": "ICMP Volume",
            "severity": "Medium",
            "details": f"Observed {icmp_count} ICMP packets."
        })
        score += 10

    risk_level = risk_from_score(score)
    summary = (
        f"PCAP analysis via PyShark completed. {packets_analyzed} packets processed with "
        f"{len(findings)} findings. Overall risk assessed as {risk_level}."
    )

    return {
        "summary": summary,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "packets_analyzed": packets_analyzed,
        "findings": findings
    }


def analyze_structured_text_file(file_path: str) -> dict:
    findings = []
    score = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    lowered = content.lower()
    lines = content.splitlines()

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    for kw in keyword_hits:
        findings.append({
            "type": "Keyword Match",
            "severity": "Medium",
            "details": f"Suspicious term detected in file: '{kw}'"
        })
        score += 7

    port_hits = 0
    for port in SUSPICIOUS_PORTS:
        count = lowered.count(str(port))
        port_hits += count

    if port_hits > 0:
        findings.append({
            "type": "Sensitive Port References",
            "severity": "High",
            "details": f"Found {port_hits} references to sensitive ports."
        })
        score += min(25, port_hits * 3)

    failed_login_hits = lowered.count("failed")
    if failed_login_hits > 3:
        findings.append({
            "type": "Authentication Failure Pattern",
            "severity": "Medium",
            "details": f"Detected {failed_login_hits} 'failed' references."
        })
        score += 12

    packets_analyzed = max(1, len(lines))
    risk_level = risk_from_score(score)
    summary = (
        f"Text-based network artifact analysis completed. {len(findings)} findings "
        f"detected across {packets_analyzed} lines. Overall risk assessed as {risk_level}."
    )

    return {
        "summary": summary,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "packets_analyzed": packets_analyzed,
        "findings": findings
    }


def analyze_input(text_input: str = "", file_path: str | None = None) -> dict:
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".pcap", ".pcapng"]:
            try:
                if pyshark is not None:
                    return analyze_pcap_with_pyshark(file_path)
            except Exception:
                pass

            try:
                if rdpcap is not None:
                    return analyze_pcap_with_scapy(file_path)
            except Exception:
                pass

            return {
                "summary": "PCAP file received, but neither PyShark nor Scapy parsing succeeded.",
                "risk_score": 10,
                "risk_level": "Low",
                "packets_analyzed": 0,
                "findings": [{
                    "type": "Parser Limitation",
                    "severity": "Low",
                    "details": "Install Wireshark/TShark for PyShark or confirm Scapy compatibility."
                }]
            }

        if ext in [".txt", ".log", ".csv", ".json"]:
            return analyze_structured_text_file(file_path)

        return {
            "summary": "Unsupported file type for analysis.",
            "risk_score": 0,
            "risk_level": "Low",
            "packets_analyzed": 0,
            "findings": [{
                "type": "Validation",
                "severity": "Low",
                "details": "File type is not supported."
            }]
        }

    return analyze_text(text_input)