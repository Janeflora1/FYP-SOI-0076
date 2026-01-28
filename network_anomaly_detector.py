#!/usr/bin/env python3
"""
Network Traffic Anomaly Detector
AI-powered detection of suspicious network patterns using machine learning
"""

import sys
from scapy.all import *
from collections import defaultdict, Counter
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings('ignore')

class NetworkAnomalyDetector:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(lambda: {'count': 0, 'bytes': 0, 'ports': set()})
        self.anomalies = []
        self.statistics = {}

        # Suspicious port numbers
        self.suspicious_ports = [
            4444, 1337, 31337, 8080, 6666, 6667, 6668, 6669,  # Common backdoor/IRC
            12345, 27374, 31336, 54321,  # Trojan ports
            3389,  # RDP (often attacked)
            445,   # SMB
            23,    # Telnet
            21,    # FTP
        ]

        # Initialize ML model
        self.anomaly_model = IsolationForest(contamination=0.05, random_state=42)

    def load_pcap(self):
        """Load and parse PCAP file"""
        print(f"[*] Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"[+] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"[!] Error loading PCAP: {e}")
            return False

    def analyze_packet(self, packet):
        """Extract features from individual packet"""
        features = {}

        if IP in packet:
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            features['length'] = len(packet)
            features['protocol'] = packet[IP].proto

            # TCP analysis
            if TCP in packet:
                features['src_port'] = packet[TCP].sport
                features['dst_port'] = packet[TCP].dport
                features['flags'] = packet[TCP].flags
                features['transport'] = 'TCP'

            # UDP analysis
            elif UDP in packet:
                features['src_port'] = packet[UDP].sport
                features['dst_port'] = packet[UDP].dport
                features['transport'] = 'UDP'

            # ICMP
            elif ICMP in packet:
                features['transport'] = 'ICMP'
                features['icmp_type'] = packet[ICMP].type

        return features

    def detect_port_scan(self):
        """Detect port scanning activity"""
        print("[*] Detecting port scans...")

        # Track connections per source IP
        src_ports = defaultdict(set)

        for packet in self.packets:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                src_ports[src_ip].add(dst_port)

        # Identify scanners (accessing many ports)
        scanners = []
        for src_ip, ports in src_ports.items():
            if len(ports) > 20:  # Threshold for port scan
                scanners.append({
                    'src_ip': src_ip,
                    'ports_scanned': len(ports),
                    'severity': 'HIGH'
                })

        return scanners

    def detect_data_exfiltration(self):
        """Detect large data transfers (potential exfiltration)"""
        print("[*] Detecting data exfiltration...")

        # Track data volume per connection
        connections = defaultdict(int)

        for packet in self.packets:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                key = f"{src}->{dst}"
                connections[key] += len(packet)

        # Identify large transfers
        exfiltration = []
        for conn, size in connections.items():
            if size > 10 * 1024 * 1024:  # > 10 MB
                src, dst = conn.split('->')
                exfiltration.append({
                    'src_ip': src,
                    'dst_ip': dst,
                    'size_mb': round(size / (1024 * 1024), 2),
                    'severity': 'CRITICAL'
                })

        return exfiltration

    def detect_c2_beacons(self):
        """Detect Command & Control beacon patterns"""
        print("[*] Detecting C2 beacon patterns...")

        # Track connection timing patterns
        connection_times = defaultdict(list)

        for packet in self.packets:
            if IP in packet and TCP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                key = f"{src}->{dst}"
                connection_times[key].append(packet.time)

        # Detect regular intervals (beaconing)
        beacons = []
        for conn, times in connection_times.items():
            if len(times) >= 5:
                intervals = np.diff(sorted(times))
                if len(intervals) > 0:
                    avg_interval = np.mean(intervals)
                    std_interval = np.std(intervals)

                    # Regular intervals indicate beaconing
                    if std_interval < avg_interval * 0.2 and avg_interval > 1:
                        src, dst = conn.split('->')
                        beacons.append({
                            'src_ip': src,
                            'dst_ip': dst,
                            'interval_sec': round(avg_interval, 2),
                            'count': len(times),
                            'severity': 'HIGH'
                        })

        return beacons

    def detect_suspicious_ports(self):
        """Detect connections to suspicious ports"""
        print("[*] Detecting suspicious port usage...")

        suspicious_conns = []

        for packet in self.packets:
            if IP in packet and TCP in packet:
                dst_port = packet[TCP].dport
                if dst_port in self.suspicious_ports:
                    suspicious_conns.append({
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'dst_port': dst_port,
                        'severity': 'MEDIUM'
                    })

        # Deduplicate
        unique_conns = []
        seen = set()
        for conn in suspicious_conns:
            key = f"{conn['src_ip']}->{conn['dst_ip']}:{conn['dst_port']}"
            if key not in seen:
                seen.add(key)
                unique_conns.append(conn)

        return unique_conns

    def ml_anomaly_detection(self):
        """Use machine learning to detect anomalous traffic patterns"""
        print("[*] Running ML-based anomaly detection...")

        # Extract features for ML
        features = []
        packet_info = []

        for packet in self.packets:
            if IP in packet:
                feature_vector = [
                    len(packet),  # Packet size
                    packet[IP].proto,  # Protocol
                ]

                if TCP in packet:
                    feature_vector.extend([
                        packet[TCP].sport,
                        packet[TCP].dport,
                        int(packet[TCP].flags)
                    ])
                elif UDP in packet:
                    feature_vector.extend([
                        packet[UDP].sport,
                        packet[UDP].dport,
                        0
                    ])
                else:
                    feature_vector.extend([0, 0, 0])

                features.append(feature_vector)
                packet_info.append({
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'size': len(packet)
                })

        if len(features) < 10:
            print("[!] Not enough packets for ML analysis")
            return []

        # Detect anomalies
        features_array = np.array(features)
        predictions = self.anomaly_model.fit_predict(features_array)

        # Collect anomalous packets
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                anomalies.append(packet_info[i])

        print(f"[+] Detected {len(anomalies)} anomalous packets via ML")

        return anomalies[:10]  # Return top 10

    def generate_statistics(self):
        """Generate traffic statistics"""
        total_packets = len(self.packets)
        total_bytes = sum(len(p) for p in self.packets)

        protocols = Counter()
        for packet in self.packets:
            if IP in packet:
                if TCP in packet:
                    protocols['TCP'] += 1
                elif UDP in packet:
                    protocols['UDP'] += 1
                elif ICMP in packet:
                    protocols['ICMP'] += 1
                else:
                    protocols['Other'] += 1

        self.statistics = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_mb': round(total_bytes / (1024 * 1024), 2),
            'protocols': dict(protocols)
        }

        return self.statistics

    def generate_report(self, port_scans, exfiltration, beacons, suspicious_ports, ml_anomalies):
        """Generate comprehensive network analysis report"""
        stats = self.generate_statistics()

        report = f"""
{'='*70}
NETWORK TRAFFIC ANOMALY DETECTION REPORT
{'='*70}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
PCAP File: {self.pcap_file}

TRAFFIC STATISTICS
------------------
Total Packets: {stats['total_packets']:,}
Total Size: {stats['total_mb']:.2f} MB

Protocol Distribution:
"""
        for proto, count in stats['protocols'].items():
            percentage = (count / stats['total_packets']) * 100
            report += f"  {proto:10s}: {count:8,} packets ({percentage:5.1f}%)\n"

        report += f"""
ANOMALY DETECTION RESULTS
-------------------------

[1] PORT SCANNING ACTIVITY
"""
        if port_scans:
            for scan in port_scans:
                report += f"    ⚠ Source IP: {scan['src_ip']}\n"
                report += f"      Ports Scanned: {scan['ports_scanned']}\n"
                report += f"      Severity: {scan['severity']}\n\n"
        else:
            report += "    ✓ No port scanning detected\n\n"

        report += f"""[2] DATA EXFILTRATION
"""
        if exfiltration:
            for exfil in exfiltration:
                report += f"    🚨 CRITICAL: Large data transfer detected\n"
                report += f"       Source: {exfil['src_ip']}\n"
                report += f"       Destination: {exfil['dst_ip']}\n"
                report += f"       Size: {exfil['size_mb']} MB\n"
                report += f"       Severity: {exfil['severity']}\n\n"
        else:
            report += "    ✓ No large data transfers detected\n\n"

        report += f"""[3] C2 BEACON PATTERNS
"""
        if beacons:
            for beacon in beacons:
                report += f"    ⚠ Beaconing detected\n"
                report += f"      Source: {beacon['src_ip']}\n"
                report += f"      Destination: {beacon['dst_ip']}\n"
                report += f"      Interval: {beacon['interval_sec']} seconds\n"
                report += f"      Count: {beacon['count']} connections\n"
                report += f"      Severity: {beacon['severity']}\n\n"
        else:
            report += "    ✓ No C2 beacon patterns detected\n\n"

        report += f"""[4] SUSPICIOUS PORT USAGE
"""
        if suspicious_ports:
            report += f"    Detected {len(suspicious_ports)} connections to suspicious ports\n"
            for conn in suspicious_ports[:5]:  # Show first 5
                report += f"      {conn['src_ip']} -> {conn['dst_ip']}:{conn['dst_port']}\n"
        else:
            report += "    ✓ No suspicious port usage detected\n\n"

        report += f"""[5] ML-BASED ANOMALY DETECTION
"""
        if ml_anomalies:
            report += f"    Detected {len(ml_anomalies)} anomalous packets\n"
            for anom in ml_anomalies[:5]:
                report += f"      {anom['src']} -> {anom['dst']} ({anom['size']} bytes)\n"
        else:
            report += "    ✓ No anomalies detected by ML model\n"

        report += f"""
{'='*70}
RECOMMENDATIONS
{'='*70}
1. Investigate all CRITICAL severity findings immediately
2. Block suspicious IPs at firewall level
3. Review connections to known C2 servers
4. Correlate with IDS/IPS logs
5. Check for malware on affected hosts
6. Review user activity on source systems
7. Update threat intelligence feeds

{'='*70}
END OF REPORT
{'='*70}
"""

        return report

    def analyze(self):
        """Execute complete network analysis workflow"""
        print(f"[*] Starting Network Anomaly Detection")
        print(f"[*] Target: {self.pcap_file}\n")

        # Load PCAP
        if not self.load_pcap():
            return

        # Run detections
        port_scans = self.detect_port_scan()
        exfiltration = self.detect_data_exfiltration()
        beacons = self.detect_c2_beacons()
        suspicious_ports = self.detect_suspicious_ports()
        ml_anomalies = self.ml_anomaly_detection()

        # Generate report
        report = self.generate_report(port_scans, exfiltration, beacons, suspicious_ports, ml_anomalies)

        # Save report
        report_file = f'network_analysis_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python network_anomaly_detector.py <pcap_file>")
        print("Example: python network_anomaly_detector.py capture.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        sys.exit(1)

    detector = NetworkAnomalyDetector(pcap_file)
    detector.analyze()

if __name__ == "__main__":
    main()
