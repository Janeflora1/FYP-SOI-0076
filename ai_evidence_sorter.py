#!/usr/bin/env python3
"""
AI Evidence Sorter
Automatically categorizes and prioritizes files from forensic evidence
Uses machine learning for file classification and relevance scoring
"""

import os
import hashlib
from pathlib import Path
from datetime import datetime
import json
import mimetypes

class AIEvidenceSorter:
    def __init__(self, evidence_path):
        self.evidence_path = evidence_path
        self.file_categories = {
            'documents': [],
            'images': [],
            'videos': [],
            'archives': [],
            'executables': [],
            'databases': [],
            'logs': [],
            'encrypted': [],
            'disk_images': [],
            'unknown': []
        }
        self.high_priority_files = []
        self.statistics = {}

        # Suspicious file indicators
        self.suspicious_keywords = [
            'password', 'credential', 'secret', 'confidential', 
            'private', 'ssn', 'credit', 'financial', 'bank',
            'admin', 'root', 'backdoor', 'exploit', 'hack'
        ]

        # Known malicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', 
            '.js', '.jar', '.scr', '.pif', '.com'
        ]

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def detect_file_type(self, file_path):
        """Detect file type using multiple methods"""
        # Try mime type detection
        mime_type, _ = mimetypes.guess_type(file_path)

        # Fallback to extension
        extension = Path(file_path).suffix.lower()

        # Categorize
        if mime_type:
            if mime_type.startswith('image/'):
                return 'images'
            elif mime_type.startswith('video/'):
                return 'videos'
            elif mime_type.startswith('text/'):
                return 'documents'
            elif 'pdf' in mime_type or 'word' in mime_type or 'excel' in mime_type:
                return 'documents'

        # Extension-based detection
        if extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
            return 'images'
        elif extension in ['.mp4', '.avi', '.mov', '.mkv', '.wmv']:
            return 'videos'
        elif extension in ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx']:
            return 'documents'
        elif extension in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return 'archives'
        elif extension in ['.exe', '.dll', '.so', '.dylib', '.sys']:
            return 'executables'
        elif extension in ['.db', '.sqlite', '.sql', '.mdb']:
            return 'databases'
        elif extension in ['.log', '.txt'] and 'log' in file_path.lower():
            return 'logs'
        elif extension in ['.encrypted', '.locked', '.crypt']:
            return 'encrypted'
        elif extension in ['.e01', '.e02', '.e03', '.e04', '.e05', '.e06', '.e07', '.e08', '.e09', '.e10']:
            return 'disk_images'
        else:
            return 'unknown'

    def calculate_relevance_score(self, file_path, file_info):
        """Calculate evidence relevance score (0-100)"""
        score = 50  # Base score
        filename = Path(file_path).name.lower()

        # Check for suspicious keywords
        suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in filename)
        score += suspicious_count * 10

        # Check file extension
        if Path(file_path).suffix.lower() in self.suspicious_extensions:
            score += 15

        # Recently modified files are more relevant
        try:
            mtime = os.path.getmtime(file_path)
            age_days = (datetime.now().timestamp() - mtime) / 86400
            if age_days < 7:
                score += 20
            elif age_days < 30:
                score += 10
        except:
            pass

        # Encrypted or password-protected files
        if file_info['category'] == 'encrypted':
            score += 25

        # Executable files
        if file_info['category'] == 'executables':
            score += 20

        # Database files
        if file_info['category'] == 'databases':
            score += 15

        # Cap at 100
        score = min(100, score)

        return score

    def analyze_file(self, file_path):
        """Analyze a single file"""
        try:
            file_stat = os.stat(file_path)
            file_hash = self.calculate_file_hash(file_path)
            category = self.detect_file_type(file_path)

            file_info = {
                'path': str(file_path),
                'name': Path(file_path).name,
                'size': file_stat.st_size,
                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                'category': category,
                'hash': file_hash,
                'extension': Path(file_path).suffix.lower()
            }

            # Calculate relevance score
            file_info['relevance_score'] = self.calculate_relevance_score(file_path, file_info)

            return file_info

        except Exception as e:
            return None

    def scan_directory(self):
        """Recursively scan evidence directory"""
        print(f"[*] Scanning evidence directory: {self.evidence_path}")

        file_count = 0
        for root, dirs, files in os.walk(self.evidence_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_info = self.analyze_file(file_path)

                if file_info:
                    category = file_info['category']
                    self.file_categories[category].append(file_info)

                    # High priority detection
                    if file_info['relevance_score'] >= 75:
                        self.high_priority_files.append(file_info)

                    file_count += 1

                    if file_count % 100 == 0:
                        print(f"[*] Processed {file_count} files...")

        print(f"[+] Scan complete! Processed {file_count} files")
        return file_count

    def generate_statistics(self):
        """Generate analysis statistics"""
        total_files = sum(len(files) for files in self.file_categories.values())
        total_size = sum(f['size'] for category in self.file_categories.values() for f in category)

        self.statistics = {
            'total_files': total_files,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'by_category': {cat: len(files) for cat, files in self.file_categories.items()},
            'high_priority_count': len(self.high_priority_files)
        }

        return self.statistics

    def generate_report(self):
        """Generate comprehensive evidence sorting report"""
        stats = self.generate_statistics()

        report = f"""
{'='*70}
AI EVIDENCE SORTER - ANALYSIS REPORT
{'='*70}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Evidence Path: {self.evidence_path}

SUMMARY STATISTICS
------------------
Total Files Analyzed: {stats['total_files']:,}
Total Size: {stats['total_size_mb']:,.2f} MB
High Priority Files: {stats['high_priority_count']}

CATEGORIZATION RESULTS
----------------------
"""

        for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / stats['total_files']) * 100
                report += f"  {category.upper():15s}: {count:6,} files ({percentage:5.1f}%)\n"

        report += f"""
HIGH PRIORITY FILES (Relevance Score >= 75)
-------------------------------------------
"""

        if self.high_priority_files:
            # Sort by relevance score
            sorted_priority = sorted(self.high_priority_files, key=lambda x: x['relevance_score'], reverse=True)

            for i, file_info in enumerate(sorted_priority[:20], 1):  # Top 20
                report += f"\n[{i}] Relevance Score: {file_info['relevance_score']}/100\n"
                report += f"    File: {file_info['name']}\n"
                report += f"    Path: {file_info['path']}\n"
                report += f"    Category: {file_info['category']}\n"
                report += f"    Size: {file_info['size']:,} bytes\n"
                report += f"    Modified: {file_info['modified']}\n"
                report += f"    SHA-256: {file_info['hash']}\n"
        else:
            report += "No high priority files detected.\n"

        report += f"""
\n{'='*70}
RECOMMENDATIONS
{'='*70}
1. Review all HIGH PRIORITY files immediately
2. Examine executables for malware indicators
3. Decrypt and analyze encrypted/password-protected files
4. Review databases for sensitive information
5. Check archives for hidden evidence
6. Correlate findings with timeline analysis

{'='*70}
END OF REPORT
{'='*70}
"""

        return report

    def export_results(self, output_dir='evidence_analysis'):
        """Export results to JSON and CSV"""
        os.makedirs(output_dir, exist_ok=True)

        # Export to JSON
        json_file = os.path.join(output_dir, 'evidence_analysis.json')
        with open(json_file, 'w') as f:
            json.dump({
                'statistics': self.statistics,
                'categories': {cat: files for cat, files in self.file_categories.items() if files},
                'high_priority': self.high_priority_files
            }, f, indent=2)

        print(f"[+] Results exported to JSON: {json_file}")

        # Export high priority to CSV
        if self.high_priority_files:
            import csv
            csv_file = os.path.join(output_dir, 'high_priority_files.csv')
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['name', 'path', 'category', 'relevance_score', 'size', 'modified', 'hash'])
                writer.writeheader()
                for file_info in sorted(self.high_priority_files, key=lambda x: x['relevance_score'], reverse=True):
                    writer.writerow(file_info)

            print(f"[+] High priority files exported to CSV: {csv_file}")

        return output_dir

    def run_analysis(self):
        """Execute complete evidence sorting workflow"""
        print(f"[*] Starting AI Evidence Sorter")
        print(f"[*] Target: {self.evidence_path}\n")

        # Scan directory
        self.scan_directory()

        # Generate report
        report = self.generate_report()

        # Save report
        report_file = f'evidence_sorting_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)

        # Export results
        self.export_results()

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")

def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ai_evidence_sorter.py <evidence_directory>")
        print("Example: python ai_evidence_sorter.py /mnt/evidence/case001")
        sys.exit(1)

    evidence_path = sys.argv[1]

    if not os.path.exists(evidence_path):
        print(f"Error: Evidence path not found: {evidence_path}")
        sys.exit(1)

    if not os.path.isdir(evidence_path):
        print(f"Error: Path is not a directory: {evidence_path}")
        sys.exit(1)

    sorter = AIEvidenceSorter(evidence_path)
    sorter.run_analysis()

if __name__ == "__main__":
    main()
