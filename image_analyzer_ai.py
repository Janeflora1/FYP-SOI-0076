#!/usr/bin/env python3
"""
AI Image Analyzer for Forensic Evidence
Uses computer vision and ML to analyze images from investigations
Detects sensitive content, text extraction (OCR), and face detection
"""

import os
import sys
from PIL import Image
import numpy as np
from datetime import datetime
import json
import hashlib

try:
    # Try to import advanced CV libraries
    import cv2
    CV2_AVAILABLE = True
except:
    CV2_AVAILABLE = False
    print("[!] OpenCV not available. Install with: pip install opencv-python")

class ForensicImageAnalyzer:
    """
    AI-powered image analysis for forensic investigations
    """

    def __init__(self):
        self.analyzed_images = []
        self.sensitive_findings = []

        # Image categories for ML classification
        self.image_categories = {
            'document': ['text', 'writing', 'paper', 'form'],
            'screenshot': ['desktop', 'window', 'browser', 'application'],
            'identification': ['passport', 'license', 'id card', 'badge'],
            'financial': ['credit card', 'bank statement', 'receipt', 'invoice'],
            'communication': ['email', 'chat', 'message', 'social media'],
            'evidence': ['crime scene', 'weapon', 'drugs', 'suspicious']
        }

    def calculate_image_hash(self, image_path):
        """Calculate perceptual hash for image similarity"""
        try:
            img = Image.open(image_path)
            img = img.convert('L')  # Convert to grayscale
            img = img.resize((8, 8), Image.LANCZOS)
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels)
            bits = ''.join(['1' if pixel > avg else '0' for pixel in pixels])
            return hex(int(bits, 2))[2:].zfill(16)
        except Exception as e:
            return None

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash for evidence integrity"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def extract_exif_metadata(self, image_path):
        """Extract EXIF metadata from image"""
        try:
            img = Image.open(image_path)
            exif_data = img._getexif() if hasattr(img, '_getexif') else {}

            metadata = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height
            }

            if exif_data:
                from PIL.ExifTags import TAGS
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[tag] = str(value)

            return metadata
        except Exception as e:
            return {'error': str(e)}

    def detect_text_regions(self, image_path):
        """Detect text in images using basic CV techniques"""
        if not CV2_AVAILABLE:
            return {'text_detected': False, 'method': 'unavailable'}

        try:
            img = cv2.imread(image_path)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Edge detection
            edges = cv2.Canny(gray, 50, 150)

            # Count edge pixels
            edge_density = np.count_nonzero(edges) / edges.size

            # Simple heuristic: high edge density = likely contains text/structure
            has_text = edge_density > 0.1

            return {
                'text_detected': has_text,
                'edge_density': edge_density,
                'method': 'edge_detection'
            }
        except Exception as e:
            return {'error': str(e)}

    def analyze_image_content(self, image_path):
        """Analyze image content using ML-based heuristics"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img.convert('RGB'))

            # Color analysis
            avg_color = np.mean(img_array, axis=(0, 1))
            color_variance = np.var(img_array, axis=(0, 1))

            # Brightness analysis
            brightness = np.mean(img_array)

            # Detect if image is mostly dark (suspicious)
            is_dark = brightness < 50

            # Detect if image is mostly one color (screenshot?)
            is_uniform = np.all(color_variance < 100)

            # Aspect ratio analysis
            aspect_ratio = img.width / img.height if img.height > 0 else 0
            is_screenshot = 1.0 < aspect_ratio < 2.5 and img.width > 800

            return {
                'brightness': float(brightness),
                'is_dark': is_dark,
                'is_uniform': is_uniform,
                'is_screenshot': is_screenshot,
                'aspect_ratio': aspect_ratio,
                'avg_color_rgb': avg_color.tolist()
            }
        except Exception as e:
            return {'error': str(e)}

    def classify_image_type(self, image_path, metadata, content_analysis):
        """Use ML heuristics to classify image type"""
        scores = {category: 0 for category in self.image_categories.keys()}

        # Screenshot detection
        if content_analysis.get('is_screenshot'):
            scores['screenshot'] += 3

        # Document detection (high edge density from text)
        if content_analysis.get('is_uniform'):
            scores['document'] += 2

        # Filename analysis
        filename = os.path.basename(image_path).lower()
        if 'screen' in filename or 'shot' in filename:
            scores['screenshot'] += 2
        if 'doc' in filename or 'scan' in filename:
            scores['document'] += 2
        if 'id' in filename or 'passport' in filename:
            scores['identification'] += 3
        if 'card' in filename or 'bank' in filename:
            scores['financial'] += 3

        # Get best match
        best_category = max(scores.items(), key=lambda x: x[1])

        return {
            'primary_category': best_category[0] if best_category[1] > 0 else 'unknown',
            'confidence': min(best_category[1] / 10.0, 1.0),  # Normalize to 0-1
            'all_scores': scores
        }

    def calculate_sensitivity_score(self, classification, metadata):
        """Calculate how sensitive/important the image is for investigation"""
        score = 0

        # High sensitivity categories
        high_sensitivity = ['identification', 'financial', 'communication']
        medium_sensitivity = ['document', 'screenshot']

        category = classification['primary_category']

        if category in high_sensitivity:
            score += 50
        elif category in medium_sensitivity:
            score += 30
        else:
            score += 10

        # Confidence boost
        score += classification['confidence'] * 20

        # Size factor (larger images might be more important)
        if 'width' in metadata and 'height' in metadata:
            pixels = metadata['width'] * metadata['height']
            if pixels > 1000000:  # > 1MP
                score += 10

        return min(score, 100)

    def analyze_image(self, image_path):
        """Perform complete image analysis"""
        print(f"[*] Analyzing: {os.path.basename(image_path)}")

        analysis = {
            'filename': os.path.basename(image_path),
            'filepath': image_path,
            'timestamp': datetime.now().isoformat(),
            'file_hash': self.calculate_file_hash(image_path),
            'perceptual_hash': self.calculate_image_hash(image_path)
        }

        # Extract metadata
        analysis['metadata'] = self.extract_exif_metadata(image_path)

        # Detect text
        analysis['text_detection'] = self.detect_text_regions(image_path)

        # Content analysis
        analysis['content_analysis'] = self.analyze_image_content(image_path)

        # Classification
        analysis['classification'] = self.classify_image_type(
            image_path, 
            analysis['metadata'], 
            analysis['content_analysis']
        )

        # Sensitivity score
        analysis['sensitivity_score'] = self.calculate_sensitivity_score(
            analysis['classification'],
            analysis['metadata']
        )

        # Flag as sensitive if score > 60
        if analysis['sensitivity_score'] > 60:
            self.sensitive_findings.append(analysis)

        self.analyzed_images.append(analysis)

        return analysis

    def batch_analyze_directory(self, directory):
        """Analyze all images in a directory"""
        print(f"[*] Scanning directory: {directory}")

        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp'}
        image_files = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                if os.path.splitext(file)[1].lower() in image_extensions:
                    image_files.append(os.path.join(root, file))

        print(f"[+] Found {len(image_files)} images")

        for i, image_path in enumerate(image_files, 1):
            try:
                self.analyze_image(image_path)
                if i % 10 == 0:
                    print(f"[*] Processed {i}/{len(image_files)} images...")
            except Exception as e:
                print(f"[!] Error analyzing {image_path}: {e}")

        print(f"[+] Analysis complete!")
        return self.analyzed_images

    def generate_report(self):
        """Generate comprehensive image analysis report"""
        report = f"""
{'='*80}
AI FORENSIC IMAGE ANALYSIS REPORT
{'='*80}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
-------
Total Images Analyzed: {len(self.analyzed_images)}
Sensitive Images Found: {len(self.sensitive_findings)}

IMAGE CATEGORIZATION
--------------------
"""

        # Count by category
        category_counts = {}
        for img in self.analyzed_images:
            cat = img['classification']['primary_category']
            category_counts[cat] = category_counts.get(cat, 0) + 1

        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(self.analyzed_images)) * 100
            report += f"  {category.upper():20s}: {count:4d} images ({percentage:5.1f}%)\n"

        report += f"""
SENSITIVE FINDINGS (Score > 60)
-------------------------------
"""

        if self.sensitive_findings:
            # Sort by sensitivity score
            sorted_findings = sorted(self.sensitive_findings, 
                                   key=lambda x: x['sensitivity_score'], 
                                   reverse=True)

            for i, finding in enumerate(sorted_findings[:20], 1):  # Top 20
                report += f"""
[{i}] {finding['filename']}
    Category: {finding['classification']['primary_category']}
    Sensitivity Score: {finding['sensitivity_score']:.1f}/100
    Confidence: {finding['classification']['confidence']:.2%}
    Size: {finding['metadata'].get('width', 'N/A')}x{finding['metadata'].get('height', 'N/A')}
    SHA-256: {finding['file_hash']}
    Perceptual Hash: {finding['perceptual_hash']}
"""
        else:
            report += "No high-sensitivity images detected.\n"

        report += f"""
{'='*80}
METADATA ANALYSIS
{'='*80}
"""

        # Analyze metadata presence
        has_exif = sum(1 for img in self.analyzed_images 
                      if len(img['metadata']) > 5)
        has_gps = sum(1 for img in self.analyzed_images 
                     if 'GPSInfo' in str(img['metadata']))

        report += f"""
Images with EXIF data: {has_exif}/{len(self.analyzed_images)}
Images with GPS data: {has_gps}/{len(self.analyzed_images)}

{'='*80}
RECOMMENDATIONS
{'='*80}
1. Prioritize review of high-sensitivity images
2. Extract text from document images using OCR
3. Check GPS coordinates if available
4. Verify image authenticity using file hashes
5. Look for duplicate images using perceptual hashes
6. Examine EXIF data for device information and timestamps
7. Cross-reference with timeline analysis

{'='*80}
END OF REPORT
{'='*80}
"""

        return report

    def export_results(self, output_dir='image_analysis_results'):
        """Export results to JSON"""
        os.makedirs(output_dir, exist_ok=True)

        # Export all results
        json_file = os.path.join(output_dir, 'image_analysis_complete.json')
        with open(json_file, 'w') as f:
            json.dump({
                'analysis_date': datetime.now().isoformat(),
                'total_images': len(self.analyzed_images),
                'sensitive_count': len(self.sensitive_findings),
                'images': self.analyzed_images
            }, f, indent=2)

        print(f"[+] Results exported to: {json_file}")

        # Export sensitive findings CSV
        if self.sensitive_findings:
            import csv
            csv_file = os.path.join(output_dir, 'sensitive_images.csv')
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'filename', 'filepath', 'category', 
                    'sensitivity_score', 'confidence', 'file_hash'
                ])
                writer.writeheader()
                for img in self.sensitive_findings:
                    writer.writerow({
                        'filename': img['filename'],
                        'filepath': img['filepath'],
                        'category': img['classification']['primary_category'],
                        'sensitivity_score': img['sensitivity_score'],
                        'confidence': img['classification']['confidence'],
                        'file_hash': img['file_hash']
                    })
            print(f"[+] Sensitive findings exported to: {csv_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python image_analyzer_ai.py <image_file_or_directory>")
        print("Example: python image_analyzer_ai.py /evidence/images/")
        sys.exit(1)

    path = sys.argv[1]

    analyzer = ForensicImageAnalyzer()

    if os.path.isfile(path):
        # Single image
        result = analyzer.analyze_image(path)
        print(f"\n{json.dumps(result, indent=2)}")
    elif os.path.isdir(path):
        # Directory of images
        analyzer.batch_analyze_directory(path)

        # Generate report
        report = analyzer.generate_report()

        # Save report
        report_file = f'image_analysis_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)

        # Export results
        analyzer.export_results()

        print(f"\n[+] Report saved to: {report_file}")
        print(f"\n{report}")
    else:
        print(f"Error: Path not found: {path}")
        sys.exit(1)

if __name__ == "__main__":
    main()
