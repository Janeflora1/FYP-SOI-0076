#!/usr/bin/env python3
"""
Memory Analysis Automation Script
Automates Volatility Framework analysis for memory dumps
"""

import os
import sys
import subprocess
from datetime import datetime

class MemoryAnalyzer:
    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.results = {}
        self.output_dir = f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_volatility_plugin(self, plugin_name):
        """Run a Volatility 3 plugin and capture output"""
        try:
            cmd = [
                'vol', '-f', self.dump_path,
                plugin_name
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except Exception as e:
            return f"Error running {plugin_name}: {str(e)}"

    def analyze_processes(self):
        """Analyze running processes"""
        print("[*] Analyzing processes...")

        # List all processes
        pslist = self.run_volatility_plugin('windows.pslist.PsList')
        self.results['pslist'] = pslist

        # Process tree
        pstree = self.run_volatility_plugin('windows.pstree.PsTree')
        self.results['pstree'] = pstree

        # Find injected code
        malfind = self.run_volatility_plugin('windows.malfind.Malfind')
        self.results['malfind'] = malfind

        return self.detect_suspicious_processes(pslist)

    def analyze_network(self):
        """Analyze network connections"""
        print("[*] Analyzing network connections...")

        netscan = self.run_volatility_plugin('windows.netscan.NetScan')
        self.results['netscan'] = netscan

        return self.parse_network_connections(netscan)

    def analyze_registry(self):
        """Analyze Windows registry"""
        print("[*] Analyzing registry hives...")

        hivelist = self.run_volatility_plugin('windows.registry.hivelist.HiveList')
        self.results['hivelist'] = hivelist

        return hivelist

    def detect_suspicious_processes(self, pslist_output):
        """Detect suspicious process indicators"""
        suspicious = []

        # Common suspicious indicators
        suspicious_paths = ['\\Users\\Public\\', '\\Temp\\', '\\AppData\\Local\\Temp\\']
        suspicious_names = ['svchost.exe', 'lsass.exe', 'csrss.exe']

        lines = pslist_output.split('\n')
        for line in lines:
            # Check for processes in suspicious locations
            for path in suspicious_paths:
                if path.lower() in line.lower():
                    suspicious.append({
                        'reason': 'Suspicious path',
                        'details': line.strip()
                    })

            # Check for masquerading processes
            for name in suspicious_names:
                if name in line.lower() and 'system32' not in line.lower():
                    suspicious.append({
                        'reason': 'Process masquerading',
                        'details': line.strip()
                    })

        return suspicious

    def parse_network_connections(self, netscan_output):
        """Parse network connections for suspicious activity"""
        connections = []
        suspicious_ports = [4444, 1337, 31337, 8080, 443]

        lines = netscan_output.split('\n')
        for line in lines:
            if 'ESTABLISHED' in line or 'LISTENING' in line:
                connections.append(line.strip())

        return connections

    def generate_report(self, suspicious_processes, network_connections):
        """Generate comprehensive analysis report"""
        report = f"""
========================================
MEMORY FORENSICS ANALYSIS REPORT
========================================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Memory Dump: {self.dump_path}
Output Directory: {self.output_dir}

EXECUTIVE SUMMARY
-----------------
Total Suspicious Processes: {len(suspicious_processes)}
Network Connections Found: {len(network_connections)}

SUSPICIOUS PROCESSES
--------------------
"""

        if suspicious_processes:
            for i, proc in enumerate(suspicious_processes, 1):
                report += f"\n{i}. {proc['reason']}\n"
                report += f"   Details: {proc['details']}\n"
        else:
            report += "No suspicious processes detected.\n"

        report += f"""
NETWORK CONNECTIONS
-------------------
"""
        if network_connections:
            for conn in network_connections[:20]:  # Show first 20
                report += f"{conn}\n"
        else:
            report += "No active connections found.\n"

        report += f"""
\n========================================
END OF REPORT
========================================
"""

        # Save report
        report_path = os.path.join(self.output_dir, 'analysis_report.txt')
        with open(report_path, 'w') as f:
            f.write(report)

        return report, report_path

    def run_full_analysis(self):
        """Execute complete memory analysis workflow"""
        print(f"[*] Starting memory analysis of: {self.dump_path}")
        print(f"[*] Output directory: {self.output_dir}")

        # Analyze processes
        suspicious_processes = self.analyze_processes()

        # Analyze network
        network_connections = self.analyze_network()

        # Analyze registry
        self.analyze_registry()

        # Generate report
        report, report_path = self.generate_report(suspicious_processes, network_connections)

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_path}")
        print(f"\n{report}")

        return self.results

def main():
    if len(sys.argv) < 2:
        print("Usage: python memory_analyzer.py <memory_dump_path>")
        print("Example: python memory_analyzer.py evidence.mem")
        sys.exit(1)

    dump_path = sys.argv[1]

    if not os.path.exists(dump_path):
        print(f"Error: Memory dump not found: {dump_path}")
        sys.exit(1)

    analyzer = MemoryAnalyzer(dump_path)
    analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
