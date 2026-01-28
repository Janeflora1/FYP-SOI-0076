#!/usr/bin/env python3
"""
Automated Timeline Builder
Creates comprehensive forensic timelines from multiple evidence sources
"""

import os
import sys
import csv
from datetime import datetime
import json

class TimelineBuilder:
    def __init__(self):
        self.events = []
        self.sources = set()

    def parse_file_system_timeline(self, timeline_file):
        """Parse file system MAC timeline (from log2timeline/plaso)"""
        print(f"[*] Parsing file system timeline: {timeline_file}")

        try:
            with open(timeline_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        event = {
                            'timestamp': row.get('date', row.get('timestamp', '')),
                            'source': 'File System',
                            'event_type': row.get('type', 'File Activity'),
                            'description': row.get('description', row.get('filename', '')),
                            'details': row.get('message', '')
                        }
                        self.events.append(event)
                        self.sources.add('File System')
                    except Exception as e:
                        continue
        except Exception as e:
            print(f"[!] Error parsing file system timeline: {e}")

    def parse_windows_events(self, event_log_file):
        """Parse Windows Event Log export (CSV format)"""
        print(f"[*] Parsing Windows Event Log: {event_log_file}")

        try:
            with open(event_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Try to detect if it's CSV
                content = f.read()
                f.seek(0)

                # Simple event ID extraction
                import re
                event_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*Event.*ID[:\s]*(\d+)'
                matches = re.finditer(event_pattern, content, re.IGNORECASE)

                for match in matches:
                    timestamp = match.group(1)
                    event_id = match.group(2)

                    event = {
                        'timestamp': timestamp,
                        'source': 'Windows Event Log',
                        'event_type': f'Event ID {event_id}',
                        'description': self._get_event_description(event_id),
                        'details': ''
                    }
                    self.events.append(event)
                    self.sources.add('Windows Event Log')

        except Exception as e:
            print(f"[!] Error parsing Windows events: {e}")

    def parse_network_log(self, network_log_file):
        """Parse network connection log"""
        print(f"[*] Parsing network log: {network_log_file}")

        try:
            with open(network_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Simple timestamp extraction
                    import re
                    timestamp_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                    match = re.search(timestamp_pattern, line)

                    if match:
                        timestamp = match.group(1)
                        event = {
                            'timestamp': timestamp,
                            'source': 'Network Traffic',
                            'event_type': 'Network Connection',
                            'description': line.strip()[:100],
                            'details': line.strip()
                        }
                        self.events.append(event)
                        self.sources.add('Network Traffic')

        except Exception as e:
            print(f"[!] Error parsing network log: {e}")

    def parse_browser_history(self, history_file):
        """Parse browser history (simple format)"""
        print(f"[*] Parsing browser history: {history_file}")

        try:
            with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'http' in line.lower():
                        event = {
                            'timestamp': datetime.now().isoformat(),
                            'source': 'Browser History',
                            'event_type': 'Web Access',
                            'description': line.strip()[:100],
                            'details': line.strip()
                        }
                        self.events.append(event)
                        self.sources.add('Browser History')

        except Exception as e:
            print(f"[!] Error parsing browser history: {e}")

    def _get_event_description(self, event_id):
        """Get description for Windows Event ID"""
        descriptions = {
            '4624': 'Successful Login',
            '4625': 'Failed Login',
            '4672': 'Special Privileges Assigned',
            '4720': 'User Account Created',
            '4732': 'User Added to Security Group',
            '7045': 'New Service Installed',
            '4688': 'Process Creation',
            '4104': 'PowerShell Script Block'
        }
        return descriptions.get(event_id, f'Event ID {event_id}')

    def sort_timeline(self):
        """Sort all events chronologically"""
        print(f"[*] Sorting {len(self.events)} events...")

        def parse_timestamp(event):
            try:
                # Try multiple timestamp formats
                ts = event['timestamp']
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']:
                    try:
                        return datetime.strptime(ts, fmt)
                    except:
                        continue
                return datetime.min
            except:
                return datetime.min

        self.events.sort(key=parse_timestamp)

    def identify_key_events(self):
        """Identify critical events in timeline"""
        key_events = []

        keywords = [
            'failed', 'administrator', 'privilege', 'escalation',
            'malware', 'suspicious', 'unauthorized', 'deleted',
            'encrypted', 'ransom', 'exploit', 'backdoor'
        ]

        for event in self.events:
            desc_lower = event['description'].lower()
            if any(keyword in desc_lower for keyword in keywords):
                event['is_key_event'] = True
                key_events.append(event)

        return key_events

    def generate_timeline_report(self):
        """Generate comprehensive timeline report"""
        key_events = self.identify_key_events()

        report = f"""
{'='*70}
AUTOMATED FORENSIC TIMELINE REPORT
{'='*70}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
-------
Total Events: {len(self.events):,}
Key Events: {len(key_events):,}
Data Sources: {', '.join(sorted(self.sources))}

CHRONOLOGICAL TIMELINE
----------------------
"""

        # Show all events (or first 100 if too many)
        display_events = self.events[:100] if len(self.events) > 100 else self.events

        for event in display_events:
            marker = "🔴 KEY" if event.get('is_key_event') else "   "
            report += f"\n{marker} [{event['timestamp']}]\n"
            report += f"    Source: {event['source']}\n"
            report += f"    Type: {event['event_type']}\n"
            report += f"    Description: {event['description'][:80]}\n"

        if len(self.events) > 100:
            report += f"\n... ({len(self.events) - 100} more events)\n"

        report += f"""
\nKEY EVENTS SUMMARY
------------------
"""

        if key_events:
            for i, event in enumerate(key_events[:20], 1):  # Top 20 key events
                report += f"\n[{i}] {event['timestamp']}\n"
                report += f"    {event['description'][:100]}\n"
        else:
            report += "No key events identified.\n"

        report += f"""
\n{'='*70}
ANALYSIS RECOMMENDATIONS
{'='*70}
1. Focus on KEY EVENTS marked with 🔴
2. Correlate events across different sources
3. Look for temporal relationships between events
4. Identify gaps or missing time periods
5. Cross-reference with known attack patterns
6. Verify timestamps for accuracy
7. Document causal relationships

{'='*70}
END OF TIMELINE REPORT
{'='*70}
"""

        return report

    def export_to_csv(self, output_file='forensic_timeline.csv'):
        """Export timeline to CSV format"""
        print(f"[*] Exporting timeline to CSV: {output_file}")

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['timestamp', 'source', 'event_type', 'description', 'details', 'is_key_event']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for event in self.events:
                writer.writerow({
                    'timestamp': event['timestamp'],
                    'source': event['source'],
                    'event_type': event['event_type'],
                    'description': event['description'],
                    'details': event.get('details', ''),
                    'is_key_event': event.get('is_key_event', False)
                })

        print(f"[+] Timeline exported to: {output_file}")

    def export_to_json(self, output_file='forensic_timeline.json'):
        """Export timeline to JSON format"""
        print(f"[*] Exporting timeline to JSON: {output_file}")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'generated': datetime.now().isoformat(),
                    'total_events': len(self.events),
                    'sources': list(self.sources)
                },
                'events': self.events
            }, f, indent=2)

        print(f"[+] Timeline exported to: {output_file}")

    def build_timeline(self, input_files):
        """Main timeline building workflow"""
        print(f"[*] Building forensic timeline from {len(input_files)} source(s)\n")

        # Parse all input files
        for file_path in input_files:
            if not os.path.exists(file_path):
                print(f"[!] File not found: {file_path}")
                continue

            # Detect file type and parse accordingly
            filename = os.path.basename(file_path).lower()

            if 'timeline' in filename or 'filesystem' in filename:
                self.parse_file_system_timeline(file_path)
            elif 'event' in filename or 'security' in filename:
                self.parse_windows_events(file_path)
            elif 'network' in filename or 'pcap' in filename or 'traffic' in filename:
                self.parse_network_log(file_path)
            elif 'history' in filename or 'browser' in filename:
                self.parse_browser_history(file_path)
            else:
                # Try to auto-detect
                print(f"[*] Auto-detecting format for: {file_path}")
                self.parse_file_system_timeline(file_path)

        # Sort timeline
        self.sort_timeline()

        # Generate report
        report = self.generate_timeline_report()

        # Save report
        report_file = f'timeline_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)

        # Export to CSV and JSON
        self.export_to_csv()
        self.export_to_json()

        print(f"\n[+] Timeline building complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python timeline_builder.py <file1> [file2] [file3] ...")
        print("Example: python timeline_builder.py filesystem_timeline.csv windows_events.txt network.log")
        sys.exit(1)

    input_files = sys.argv[1:]

    builder = TimelineBuilder()
    builder.build_timeline(input_files)

if __name__ == "__main__":
    main()
