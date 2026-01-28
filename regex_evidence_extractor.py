#!/usr/bin/env python3
"""
Regex Evidence Extractor
Advanced pattern matching for finding key evidence in forensic data
Uses regular expressions to extract IPs, emails, URLs, hashes, credit cards, etc.
"""

import re
import os
import sys
from datetime import datetime
from collections import defaultdict
import json

class RegexEvidenceExtractor:
    """
    Extracts forensic evidence using advanced regular expression patterns
    """

    def __init__(self):
        # Define regex patterns for various evidence types
        self.patterns = {
            'ipv4': {
                'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IPv4 Addresses'
            },
            'ipv6': {
                'pattern': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
                'description': 'IPv6 Addresses'
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email Addresses'
            },
            'url': {
                'pattern': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
                'description': 'URLs'
            },
            'domain': {
                'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                'description': 'Domain Names'
            },
            'md5': {
                'pattern': r'\b[a-fA-F0-9]{32}\b',
                'description': 'MD5 Hashes'
            },
            'sha1': {
                'pattern': r'\b[a-fA-F0-9]{40}\b',
                'description': 'SHA-1 Hashes'
            },
            'sha256': {
                'pattern': r'\b[a-fA-F0-9]{64}\b',
                'description': 'SHA-256 Hashes'
            },
            'credit_card': {
                'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                'description': 'Credit Card Numbers'
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'description': 'Social Security Numbers (US)'
            },
            'phone_us': {
                'pattern': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
                'description': 'US Phone Numbers'
            },
            'bitcoin': {
                'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                'description': 'Bitcoin Addresses'
            },
            'mac_address': {
                'pattern': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
                'description': 'MAC Addresses'
            },
            'windows_path': {
                'pattern': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
                'description': 'Windows File Paths'
            },
            'linux_path': {
                'pattern': r'/(?:[^/\0]+/)*[^/\0]+',
                'description': 'Linux/Unix File Paths'
            },
            'registry_key': {
                'pattern': r'HKEY_[A-Z_]+\\[\\A-Za-z0-9_]+',
                'description': 'Windows Registry Keys'
            },
            'cvv': {
                'pattern': r'\b\d{3,4}\b(?=.*(?:cvv|security|code))',
                'description': 'CVV Codes'
            },
            'private_key': {
                'pattern': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                'description': 'Private Key Headers'
            },
            'aws_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Keys'
            },
            'base64': {
                'pattern': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
                'description': 'Base64 Encoded Data (potential)'
            }
        }

        # Compile patterns for efficiency
        self.compiled_patterns = {
            name: re.compile(info['pattern']) 
            for name, info in self.patterns.items()
        }

        self.findings = defaultdict(list)
        self.stats = defaultdict(int)

    def extract_from_text(self, text, pattern_names=None):
        """Extract evidence from text using specified patterns"""
        if pattern_names is None:
            pattern_names = self.patterns.keys()

        results = {}

        for name in pattern_names:
            if name not in self.compiled_patterns:
                continue

            pattern = self.compiled_patterns[name]
            matches = pattern.findall(text)

            # Deduplicate
            unique_matches = list(set(matches))

            if unique_matches:
                results[name] = unique_matches
                self.stats[name] += len(unique_matches)

        return results

    def extract_from_file(self, file_path, pattern_names=None):
        """Extract evidence from a file"""
        print(f"[*] Scanning file: {os.path.basename(file_path)}")

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return {}

        results = self.extract_from_text(content, pattern_names)

        # Store findings with context
        for evidence_type, matches in results.items():
            for match in matches:
                # Find context around match
                pos = content.find(str(match))
                context_start = max(0, pos - 50)
                context_end = min(len(content), pos + len(str(match)) + 50)
                context = content[context_start:context_end]

                self.findings[evidence_type].append({
                    'value': match,
                    'file': file_path,
                    'context': context,
                    'timestamp': datetime.now().isoformat()
                })

        return results

    def scan_directory(self, directory, extensions=None, pattern_names=None):
        """Recursively scan directory for evidence"""
        print(f"[*] Scanning directory: {directory}")

        if extensions is None:
            # Common text file extensions
            extensions = {'.txt', '.log', '.csv', '.json', '.xml', '.html', 
                         '.md', '.py', '.js', '.sql', '.conf', '.ini'}

        file_count = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                if os.path.splitext(file)[1].lower() in extensions:
                    file_path = os.path.join(root, file)
                    self.extract_from_file(file_path, pattern_names)
                    file_count += 1

                    if file_count % 10 == 0:
                        print(f"[*] Scanned {file_count} files...")

        print(f"[+] Scanned {file_count} files")
        return self.findings

    def validate_findings(self):
        """Apply additional validation to reduce false positives"""
        validated = {}

        # Validate IP addresses
        if 'ipv4' in self.findings:
            valid_ips = []
            for finding in self.findings['ipv4']:
                ip = finding['value']
                octets = ip.split('.')
                if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                    # Filter out common false positives
                    if not (ip.startswith('0.') or ip.startswith('255.')):
                        valid_ips.append(finding)
            validated['ipv4'] = valid_ips

        # Validate credit cards (Luhn algorithm)
        if 'credit_card' in self.findings:
            valid_cards = []
            for finding in self.findings['credit_card']:
                number = re.sub(r'[-\s]', '', finding['value'])
                if self.luhn_check(number):
                    valid_cards.append(finding)
            validated['credit_card'] = valid_cards

        # Copy other findings
        for key, value in self.findings.items():
            if key not in validated:
                validated[key] = value

        self.findings = validated
        return validated

    def luhn_check(self, card_number):
        """Validate credit card using Luhn algorithm"""
        try:
            digits = [int(d) for d in str(card_number)]
            checksum = 0
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return checksum % 10 == 0
        except:
            return False

    def generate_report(self):
        """Generate comprehensive evidence extraction report"""
        report = f"""
{'='*80}
REGEX EVIDENCE EXTRACTION REPORT
{'='*80}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
-------
Evidence Types Found: {len([k for k, v in self.findings.items() if v])}
Total Artifacts Extracted: {sum(len(v) for v in self.findings.values())}

EVIDENCE BREAKDOWN
------------------
"""

        for evidence_type in sorted(self.findings.keys()):
            if not self.findings[evidence_type]:
                continue

            count = len(self.findings[evidence_type])
            description = self.patterns[evidence_type]['description']
            report += f"\n[{evidence_type.upper()}] - {description}\n"
            report += f"  Count: {count} unique artifacts\n"

            # Show top 10 findings
            unique_values = {}
            for finding in self.findings[evidence_type]:
                val = str(finding['value'])
                if val not in unique_values:
                    unique_values[val] = []
                unique_values[val].append(finding['file'])

            report += f"  Top {min(10, len(unique_values))} findings:\n"
            for i, (value, files) in enumerate(sorted(unique_values.items())[:10], 1):
                report += f"    {i}. {value}\n"
                report += f"       Found in: {os.path.basename(files[0])}\n"

        report += f"""
\n{'='*80}
SENSITIVE DATA DETECTED
{'='*80}
"""

        sensitive_types = ['credit_card', 'ssn', 'private_key', 'aws_key', 'cvv']
        sensitive_found = any(self.findings.get(t) for t in sensitive_types)

        if sensitive_found:
            report += "⚠️  WARNING: Potentially sensitive data detected!\n\n"
            for stype in sensitive_types:
                if self.findings.get(stype):
                    count = len(self.findings[stype])
                    report += f"  {stype.upper()}: {count} instances\n"
        else:
            report += "✓ No highly sensitive data patterns detected\n"

        report += f"""
\n{'='*80}
NETWORK INDICATORS
{'='*80}
"""

        network_types = ['ipv4', 'ipv6', 'domain', 'url', 'mac_address']
        network_found = any(self.findings.get(t) for t in network_types)

        if network_found:
            for ntype in network_types:
                if self.findings.get(ntype):
                    unique_count = len(set(f['value'] for f in self.findings[ntype]))
                    report += f"  {ntype.upper()}: {unique_count} unique\n"

        report += f"""
\n{'='*80}
RECOMMENDATIONS
{'='*80}
1. Investigate all sensitive data findings immediately
2. Correlate IP addresses with network logs
3. Check URLs/domains against threat intelligence
4. Verify credit card numbers and SSNs for relevance
5. Extract and analyze Base64 encoded data
6. Review file paths for suspicious locations
7. Check hashes against malware databases
8. Investigate private keys and API credentials

{'='*80}
END OF REPORT
{'='*80}
"""

        return report

    def export_results(self, output_dir='evidence_extraction_results'):
        """Export findings to JSON and CSV"""
        os.makedirs(output_dir, exist_ok=True)

        # Export to JSON
        json_file = os.path.join(output_dir, 'evidence_extraction.json')
        with open(json_file, 'w') as f:
            json.dump({
                'analysis_date': datetime.now().isoformat(),
                'total_artifacts': sum(len(v) for v in self.findings.values()),
                'findings': {k: v for k, v in self.findings.items() if v}
            }, f, indent=2)

        print(f"[+] Results exported to: {json_file}")

        # Export each evidence type to CSV
        for evidence_type, findings in self.findings.items():
            if not findings:
                continue

            import csv
            csv_file = os.path.join(output_dir, f'{evidence_type}_findings.csv')
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['value', 'file', 'context', 'timestamp'])
                writer.writeheader()
                for finding in findings:
                    writer.writerow({
                        'value': finding['value'],
                        'file': finding['file'],
                        'context': finding['context'][:100],
                        'timestamp': finding['timestamp']
                    })

            print(f"[+] {evidence_type} findings exported to: {csv_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python regex_evidence_extractor.py <file_or_directory>")
        print("Example: python regex_evidence_extractor.py /evidence/logs/")
        sys.exit(1)

    path = sys.argv[1]

    extractor = RegexEvidenceExtractor()

    if os.path.isfile(path):
        # Single file
        results = extractor.extract_from_file(path)
        print(f"\nFindings: {json.dumps(results, indent=2)}")
    elif os.path.isdir(path):
        # Directory
        extractor.scan_directory(path)

        # Validate findings
        extractor.validate_findings()

        # Generate report
        report = extractor.generate_report()

        # Save report
        report_file = f'evidence_extraction_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)

        # Export results
        extractor.export_results()

        print(f"\n[+] Report saved to: {report_file}")
        print(f"\n{report}")
    else:
        print(f"Error: Path not found: {path}")
        sys.exit(1)

if __name__ == "__main__":
    main()
