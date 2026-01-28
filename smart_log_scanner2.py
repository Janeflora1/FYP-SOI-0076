#!/usr/bin/env python3
"""
Smart Log Scanner - ML Anomaly Detection
Uses Isolation Forest machine learning to detect anomalies in system logs
Part of: Virtual Digital Forensics Lab with AI-Powered Features
"""

import os
import sys
import re
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class SmartLogScanner:
    """
    AI-powered log scanner using Isolation Forest for anomaly detection
    Detects suspicious patterns in Windows Event Logs, Linux logs, and application logs
    """

    def __init__(self, contamination=0.1):
        """
        Initialize the Smart Log Scanner

        Args:
            contamination: Expected proportion of outliers (default 0.1 = 10%)
        """
        self.contamination = contamination
        self.anomaly_detector = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            verbose=0
        )
        self.scaler = StandardScaler()
        self.logs = []
        self.features = []
        self.anomalies = []
        self.normal_logs = []

        # Known suspicious patterns for feature extraction
        self.suspicious_keywords = {
            'authentication': ['failed', 'failure', 'invalid', 'denied', 'unauthorized'],
            'privilege': ['sudo', 'privilege', 'administrator', 'root', 'elevated'],
            'execution': ['exec', 'execute', 'powershell', 'cmd.exe', 'bash', 'script'],
            'network': ['port', 'scan', 'connect', 'listening', 'socket'],
            'malware': ['malware', 'virus', 'trojan', 'backdoor', 'exploit'],
            'data': ['dump', 'export', 'exfil', 'transfer', 'download']
        }

        # Critical Windows Event IDs
        self.critical_event_ids = {
            4625: 'Failed Login',
            4672: 'Special Privileges Assigned',
            4720: 'User Account Created',
            4732: 'User Added to Group',
            7045: 'New Service Installed',
            4688: 'Process Creation',
            4104: 'PowerShell Script Block',
            4698: 'Scheduled Task Created',
            4776: 'Domain Controller Auth Attempt',
            1102: 'Audit Log Cleared'
        }

    def extract_features(self, log_entry):
        """
        Extract numerical features from a log entry for ML analysis

        Features:
        1. Log length
        2. Number of IP addresses
        3. Number of suspicious keywords
        4. Special character ratio
        5. Uppercase letter ratio
        6. Number of digits
        7. Number of timestamps
        8. Contains hex values (0/1)
        9. Number of port numbers
        10. Contains file path (0/1)
        11. Event ID severity (if Windows Event Log)
        12. Hour of day (0-23)
        """
        features = []

        # Feature 1: Log entry length
        log_len = len(log_entry)
        features.append(log_len)

        # Feature 2: Number of IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_count = len(re.findall(ip_pattern, log_entry))
        features.append(ip_count)

        # Feature 3: Suspicious keyword count (weighted)
        suspicious_count = 0
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword.lower() in log_entry.lower():
                    suspicious_count += 1
        features.append(suspicious_count)

        # Feature 4: Special character ratio
        special_chars = sum(1 for c in log_entry if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / log_len if log_len > 0 else 0
        features.append(special_ratio)

        # Feature 5: Uppercase ratio
        uppercase_count = sum(1 for c in log_entry if c.isupper())
        uppercase_ratio = uppercase_count / log_len if log_len > 0 else 0
        features.append(uppercase_ratio)

        # Feature 6: Number of digits
        digit_count = sum(1 for c in log_entry if c.isdigit())
        features.append(digit_count)

        # Feature 7: Timestamp count
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}:\d{2}:\d{2}',  # HH:MM:SS
            r'\d{2}/\d{2}/\d{4}'   # MM/DD/YYYY
        ]
        timestamp_count = sum(len(re.findall(pattern, log_entry)) for pattern in timestamp_patterns)
        features.append(timestamp_count)

        # Feature 8: Contains hex values
        hex_pattern = r'0x[0-9a-fA-F]+'
        has_hex = 1 if re.search(hex_pattern, log_entry) else 0
        features.append(has_hex)

        # Feature 9: Port numbers
        port_pattern = r':\d{2,5}\b'
        port_count = len(re.findall(port_pattern, log_entry))
        features.append(port_count)

        # Feature 10: Contains file path
        path_patterns = [r'[A-Za-z]:\\', r'/[a-z]+/']
        has_path = 1 if any(re.search(p, log_entry) for p in path_patterns) else 0
        features.append(has_path)

        # Feature 11: Event ID severity (Windows)
        event_id_match = re.search(r'Event(?:\s+)?ID[:\s]*(\d+)', log_entry, re.IGNORECASE)
        event_severity = 0
        if event_id_match:
            event_id = int(event_id_match.group(1))
            if event_id in self.critical_event_ids:
                event_severity = 1
        features.append(event_severity)

        # Feature 12: Hour of day (if extractable)
        hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', log_entry)
        hour = int(hour_match.group(1)) if hour_match else 12  # Default to noon
        features.append(hour)

        return features

    def load_log_file(self, log_file_path):
        """Load and parse log file"""
        print(f"[*] Loading log file: {log_file_path}")

        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                logs = [line.strip() for line in f if line.strip()]

            print(f"[+] Loaded {len(logs)} log entries")
            return logs

        except Exception as e:
            print(f"[!] Error loading log file: {e}")
            return []

    def train_and_detect(self, logs):
        """
        Train Isolation Forest model and detect anomalies

        Args:
            logs: List of log entries

        Returns:
            predictions: Array of predictions (-1 for anomaly, 1 for normal)
            anomaly_scores: Array of anomaly scores (lower = more anomalous)
        """
        print(f"[*] Extracting features from {len(logs)} log entries...")

        # Extract features for all logs
        features = []
        for log in logs:
            feature_vector = self.extract_features(log)
            features.append(feature_vector)

        # Convert to numpy array
        X = np.array(features)

        print(f"[*] Feature matrix shape: {X.shape}")
        print(f"[*] Features per log: {X.shape[1]}")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        print(f"[*] Training Isolation Forest (contamination={self.contamination})...")
        self.anomaly_detector.fit(X_scaled)

        # Predict anomalies
        predictions = self.anomaly_detector.predict(X_scaled)

        # Get anomaly scores (lower score = more anomalous)
        anomaly_scores = self.anomaly_detector.score_samples(X_scaled)

        # Store results
        self.logs = logs
        self.features = features

        # Separate anomalies and normal logs
        for i, (log, pred, score) in enumerate(zip(logs, predictions, anomaly_scores)):
            if pred == -1:  # Anomaly
                self.anomalies.append({
                    'index': i,
                    'log': log,
                    'score': score,
                    'features': features[i]
                })
            else:  # Normal
                self.normal_logs.append({
                    'index': i,
                    'log': log,
                    'score': score
                })

        print(f"[+] Detection complete!")
        print(f"[+] Anomalies detected: {len(self.anomalies)} ({len(self.anomalies)/len(logs)*100:.1f}%)")
        print(f"[+] Normal logs: {len(self.normal_logs)} ({len(self.normal_logs)/len(logs)*100:.1f}%)")

        return predictions, anomaly_scores

    def analyze_anomalies(self):
        """Analyze detected anomalies for threat patterns"""
        print("\n[*] Analyzing anomalies for threat patterns...")

        threat_categories = {
            'Authentication Failures': [],
            'Privilege Escalation': [],
            'Malicious Execution': [],
            'Network Activity': [],
            'Data Exfiltration': [],
            'System Tampering': []
        }

        for anomaly in self.anomalies:
            log = anomaly['log'].lower()

            # Categorize anomalies
            if any(kw in log for kw in self.suspicious_keywords['authentication']):
                threat_categories['Authentication Failures'].append(anomaly)

            if any(kw in log for kw in self.suspicious_keywords['privilege']):
                threat_categories['Privilege Escalation'].append(anomaly)

            if any(kw in log for kw in self.suspicious_keywords['execution']):
                threat_categories['Malicious Execution'].append(anomaly)

            if any(kw in log for kw in self.suspicious_keywords['network']):
                threat_categories['Network Activity'].append(anomaly)

            if any(kw in log for kw in self.suspicious_keywords['data']):
                threat_categories['Data Exfiltration'].append(anomaly)

            # Check for Event ID
            if any(str(event_id) in anomaly['log'] for event_id in self.critical_event_ids):
                threat_categories['System Tampering'].append(anomaly)

        return threat_categories

    def generate_report(self, threat_categories):
        """Generate comprehensive anomaly detection report"""
        report = f"""
{'='*80}
SMART LOG SCANNER - ML ANOMALY DETECTION REPORT
{'='*80}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
ML Algorithm: Isolation Forest
Contamination Rate: {self.contamination} ({self.contamination*100}% expected anomalies)

DETECTION SUMMARY
-----------------
Total Logs Analyzed: {len(self.logs):,}
Anomalies Detected: {len(self.anomalies):,} ({len(self.anomalies)/len(self.logs)*100:.1f}%)
Normal Logs: {len(self.normal_logs):,} ({len(self.normal_logs)/len(self.logs)*100:.1f}%)

ML MODEL PARAMETERS
-------------------
Algorithm: Isolation Forest
Estimators: 100 decision trees
Contamination: {self.contamination}
Features Extracted: 12 per log entry

FEATURE IMPORTANCE
------------------
1. Log Length
2. IP Address Count
3. Suspicious Keywords
4. Special Character Ratio
5. Uppercase Ratio
6. Digit Count
7. Timestamp Count
8. Hex Values Present
9. Port Numbers
10. File Path Present
11. Critical Event ID
12. Hour of Day

THREAT ANALYSIS
---------------
"""

        for category, anomalies in threat_categories.items():
            if anomalies:
                report += f"\n[{category.upper()}] - {len(anomalies)} anomalies detected\n"

                # Sort by anomaly score (most anomalous first)
                sorted_anomalies = sorted(anomalies, key=lambda x: x['score'])

                # Show top 5 for each category
                for i, anomaly in enumerate(sorted_anomalies[:5], 1):
                    report += f"\n  {i}. Anomaly Score: {anomaly['score']:.4f}\n"
                    report += f"     Log: {anomaly['log'][:100]}...\n"

                    # Show key features
                    features = anomaly['features']
                    report += f"     Features: IPs={features[1]}, Keywords={features[2]}, Ports={features[8]}\n"

        report += f"""
\nTOP 10 MOST ANOMALOUS LOGS
---------------------------
"""

        # Sort all anomalies by score
        sorted_all = sorted(self.anomalies, key=lambda x: x['score'])

        for i, anomaly in enumerate(sorted_all[:10], 1):
            report += f"\n[{i}] Score: {anomaly['score']:.4f}\n"
            report += f"    {anomaly['log'][:120]}\n"

        report += f"""
\n{'='*80}
RECOMMENDATIONS
{'='*80}
1. Investigate all anomalies with scores < -0.5 (highly anomalous)
2. Focus on Authentication Failures and Privilege Escalation
3. Correlate anomalies with network traffic and memory analysis
4. Check for temporal patterns (clustered in time)
5. Review source IPs and user accounts
6. Update security monitoring rules based on findings
7. Retrain model with confirmed threats for better detection

{'='*80}
MACHINE LEARNING INSIGHTS
{'='*80}
The Isolation Forest algorithm isolates anomalies by randomly selecting
features and split values. Anomalies require fewer splits to isolate.

Anomaly Score Interpretation:
  Score < -0.5  : Highly anomalous (HIGH PRIORITY)
  -0.5 < Score < 0 : Moderately anomalous (MEDIUM PRIORITY)
  Score > 0     : Normal behavior

{'='*80}
END OF REPORT
{'='*80}
"""

        return report

    def save_results(self, output_dir='log_scanner_results'):
        """Save anomalies and results to files"""
        os.makedirs(output_dir, exist_ok=True)

        # Save anomalies to CSV
        import csv
        anomalies_file = os.path.join(output_dir, 'anomalies.csv')
        with open(anomalies_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['index', 'score', 'log'])
            writer.writeheader()
            for anomaly in sorted(self.anomalies, key=lambda x: x['score']):
                writer.writerow({
                    'index': anomaly['index'],
                    'score': f"{anomaly['score']:.6f}",
                    'log': anomaly['log']
                })

        print(f"[+] Anomalies saved to: {anomalies_file}")

        # Save feature matrix
        feature_file = os.path.join(output_dir, 'features.csv')
        feature_names = [
            'log_length', 'ip_count', 'suspicious_keywords', 'special_char_ratio',
            'uppercase_ratio', 'digit_count', 'timestamp_count', 'has_hex',
            'port_count', 'has_path', 'critical_event', 'hour'
        ]

        df = pd.DataFrame(self.features, columns=feature_names)
        df['is_anomaly'] = [-1 if i in [a['index'] for a in self.anomalies] else 1 
                           for i in range(len(self.logs))]
        df.to_csv(feature_file, index=False)

        print(f"[+] Features saved to: {feature_file}")

    def run_analysis(self, log_file_path):
        """Main analysis workflow"""
        print(f"\n{'='*80}")
        print("SMART LOG SCANNER - ML ANOMALY DETECTION")
        print(f"{'='*80}\n")

        # Load logs
        logs = self.load_log_file(log_file_path)

        if not logs:
            print("[!] No logs to analyze")
            return

        # Train and detect
        predictions, scores = self.train_and_detect(logs)

        # Analyze anomalies
        threat_categories = self.analyze_anomalies()

        # Generate report
        report = self.generate_report(threat_categories)

        # Save report
        report_file = f'smart_log_scanner_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)

        # Save results
        self.save_results()

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python smart_log_scanner.py <log_file>")
        print("Example: python smart_log_scanner.py /var/log/auth.log")
        print("         python smart_log_scanner.py Security.evtx.txt")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    # Create scanner (10% contamination = expect 10% anomalies)
    scanner = SmartLogScanner(contamination=0.1)

    # Run analysis
    scanner.run_analysis(log_file)

if __name__ == "__main__":
    main()
