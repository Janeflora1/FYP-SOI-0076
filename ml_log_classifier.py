#!/usr/bin/env python3
"""
Advanced ML Log Classifier
Deep learning model for intelligent log classification and threat detection
Implements multiple ML algorithms for comparison
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import joblib
from datetime import datetime

class MLLogClassifier:
    """
    Machine Learning-based log classifier for security event detection
    Uses multiple ML algorithms: Random Forest, Gradient Boosting, and TF-IDF
    """

    def __init__(self):
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
        }
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.trained_model = None
        self.best_model_name = None

        # Security event categories
        self.categories = [
            'normal',
            'brute_force',
            'privilege_escalation',
            'malware_execution',
            'data_exfiltration',
            'lateral_movement',
            'reconnaissance'
        ]

    def extract_features(self, log_text):
        """Extract numerical features from log text"""
        features = []

        # Feature 1: Log length
        features.append(len(log_text))

        # Feature 2: Number of IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features.append(len(re.findall(ip_pattern, log_text)))

        # Feature 3: Number of suspicious keywords
        suspicious_words = ['failed', 'error', 'denied', 'unauthorized', 'root', 'admin']
        features.append(sum(word in log_text.lower() for word in suspicious_words))

        # Feature 4: Special characters count
        features.append(sum(not c.isalnum() and not c.isspace() for c in log_text))

        # Feature 5: Uppercase ratio
        if len(log_text) > 0:
            features.append(sum(c.isupper() for c in log_text) / len(log_text))
        else:
            features.append(0)

        # Feature 6: Number of timestamps
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}'
        features.append(len(re.findall(timestamp_pattern, log_text)))

        # Feature 7: Contains hex values
        features.append(1 if re.search(r'0x[0-9a-fA-F]+', log_text) else 0)

        # Feature 8: Port numbers
        port_pattern = r':\d{2,5}'
        features.append(len(re.findall(port_pattern, log_text)))

        return features

    def generate_synthetic_training_data(self, samples_per_category=100):
        """
        Generate synthetic training data for demonstration
        In production, use real labeled log data
        """
        print("[*] Generating synthetic training data...")

        training_data = []

        # Normal logs
        normal_templates = [
            "INFO: User login successful from IP {ip}",
            "DEBUG: Application started on port {port}",
            "INFO: Database connection established",
            "INFO: Request processed successfully in {time}ms"
        ]

        # Brute force attack logs
        brute_force_templates = [
            "WARN: Failed login attempt for user {user} from IP {ip}",
            "ERROR: Authentication failed - invalid password for {user}",
            "WARN: Multiple failed login attempts detected from {ip}",
            "ERROR: Account locked due to failed authentication"
        ]

        # Privilege escalation
        privilege_templates = [
            "WARN: User {user} attempted sudo command",
            "CRITICAL: Privilege escalation detected for user {user}",
            "ERROR: Unauthorized access to root account",
            "WARN: User added to administrators group"
        ]

        # Malware execution
        malware_templates = [
            "CRITICAL: Suspicious process detected: {process}",
            "ERROR: Malicious executable blocked: {file}",
            "WARN: PowerShell execution with encoded command",
            "CRITICAL: Ransomware behavior detected"
        ]

        # Data exfiltration
        exfiltration_templates = [
            "WARN: Large data transfer detected to {ip}",
            "CRITICAL: Sensitive file accessed: {file}",
            "ERROR: Unauthorized data export to external location",
            "WARN: Database dump initiated by {user}"
        ]

        templates_map = {
            'normal': normal_templates,
            'brute_force': brute_force_templates,
            'privilege_escalation': privilege_templates,
            'malware_execution': malware_templates,
            'data_exfiltration': exfiltration_templates
        }

        for category, templates in templates_map.items():
            for _ in range(samples_per_category):
                template = np.random.choice(templates)
                log = template.format(
                    ip=f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                    user=np.random.choice(['admin', 'user1', 'root', 'guest']),
                    port=np.random.randint(1000, 9999),
                    time=np.random.randint(10, 1000),
                    process=np.random.choice(['cmd.exe', 'powershell.exe', 'suspicious.exe']),
                    file=np.random.choice(['passwords.txt', 'database.db', 'secret.doc'])
                )
                training_data.append({'log': log, 'category': category})

        return pd.DataFrame(training_data)

    def train_models(self, df=None):
        """Train multiple ML models and select the best one"""
        if df is None:
            df = self.generate_synthetic_training_data()

        print(f"[*] Training on {len(df)} log samples...")
        print(f"[*] Categories: {df['category'].value_counts().to_dict()}")

        # Extract features
        X_text = df['log'].values
        X_numeric = np.array([self.extract_features(log) for log in X_text])

        # TF-IDF vectorization
        X_tfidf = self.vectorizer.fit_transform(X_text).toarray()

        # Combine features
        X_combined = np.hstack([X_tfidf, X_numeric])

        # Encode labels
        y = self.label_encoder.fit_transform(df['category'])

        # Scale features
        X_scaled = self.scaler.fit_transform(X_combined)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train and evaluate each model
        best_accuracy = 0
        results = {}

        print("\n[*] Training models...")
        for name, model in self.models.items():
            print(f"\n  Training {name}...")
            model.fit(X_train, y_train)

            # Predictions
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            results[name] = {
                'accuracy': accuracy,
                'confusion_matrix': confusion_matrix(y_test, y_pred),
                'classification_report': classification_report(
                    y_test, y_pred, 
                    target_names=self.label_encoder.classes_,
                    output_dict=True
                )
            }

            print(f"  {name} Accuracy: {accuracy:.4f}")

            if accuracy > best_accuracy:
                best_accuracy = accuracy
                self.trained_model = model
                self.best_model_name = name

        print(f"\n[+] Best model: {self.best_model_name} (Accuracy: {best_accuracy:.4f})")

        return results

    def predict(self, log_text):
        """Predict the category of a log entry"""
        if self.trained_model is None:
            raise ValueError("Model not trained. Call train_models() first.")

        # Extract features
        X_text = [log_text]
        X_numeric = np.array([self.extract_features(log_text)])
        X_tfidf = self.vectorizer.transform(X_text).toarray()
        X_combined = np.hstack([X_tfidf, X_numeric])
        X_scaled = self.scaler.transform(X_combined)

        # Predict
        prediction = self.trained_model.predict(X_scaled)[0]
        probabilities = self.trained_model.predict_proba(X_scaled)[0]

        category = self.label_encoder.inverse_transform([prediction])[0]
        confidence = max(probabilities)

        return {
            'category': category,
            'confidence': confidence,
            'all_probabilities': dict(zip(self.label_encoder.classes_, probabilities))
        }

    def batch_predict(self, log_file):
        """Analyze an entire log file"""
        print(f"[*] Analyzing log file: {log_file}")

        predictions = []
        threats_found = []

        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                result = self.predict(line)
                predictions.append({
                    'line_number': i,
                    'log': line[:100],
                    'category': result['category'],
                    'confidence': result['confidence']
                })

                # Flag threats
                if result['category'] != 'normal' and result['confidence'] > 0.7:
                    threats_found.append({
                        'line_number': i,
                        'log': line,
                        'threat_type': result['category'],
                        'confidence': result['confidence']
                    })

        return predictions, threats_found

    def save_model(self, filepath='ml_log_classifier.pkl'):
        """Save trained model to disk"""
        model_package = {
            'model': self.trained_model,
            'vectorizer': self.vectorizer,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'best_model_name': self.best_model_name
        }
        joblib.dump(model_package, filepath)
        print(f"[+] Model saved to {filepath}")

    def load_model(self, filepath='ml_log_classifier.pkl'):
        """Load trained model from disk"""
        model_package = joblib.load(filepath)
        self.trained_model = model_package['model']
        self.vectorizer = model_package['vectorizer']
        self.scaler = model_package['scaler']
        self.label_encoder = model_package['label_encoder']
        self.best_model_name = model_package['best_model_name']
        print(f"[+] Model loaded from {filepath}")

    def generate_report(self, predictions, threats):
        """Generate analysis report"""
        report = f"""
{'='*80}
ML LOG CLASSIFICATION REPORT
{'='*80}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Model Used: {self.best_model_name}

SUMMARY
-------
Total Logs Analyzed: {len(predictions)}
Threats Detected: {len(threats)}

THREAT BREAKDOWN
----------------
"""

        if threats:
            threat_types = {}
            for threat in threats:
                threat_type = threat['threat_type']
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                report += f"  {threat_type}: {count} occurrences\n"

            report += "\nTOP THREATS:\n"
            for i, threat in enumerate(sorted(threats, key=lambda x: x['confidence'], reverse=True)[:10], 1):
                report += f"\n[{i}] Line {threat['line_number']}\n"
                report += f"    Type: {threat['threat_type']} (Confidence: {threat['confidence']:.2%})\n"
                report += f"    Log: {threat['log'][:100]}...\n"
        else:
            report += "No threats detected.\n"

        report += f"""
{'='*80}
RECOMMENDATIONS
{'='*80}
1. Investigate all HIGH confidence threats immediately
2. Review logs around detected anomalies
3. Correlate with other security events
4. Update security rules based on findings
5. Retrain model with new threat patterns

{'='*80}
END OF REPORT
{'='*80}
"""

        return report

def main():
    import sys

    print("="*80)
    print("MACHINE LEARNING LOG CLASSIFIER")
    print("="*80)

    classifier = MLLogClassifier()

    # Train models
    print("\n[*] Training ML models...")
    results = classifier.train_models()

    # Save model
    classifier.save_model('ml_log_classifier.pkl')

    # Interactive mode or file analysis
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        predictions, threats = classifier.batch_predict(log_file)

        # Generate report
        report = classifier.generate_report(predictions, threats)

        # Save report
        report_file = f'ml_classification_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")
    else:
        # Demo mode
        print("\n[*] Demo Mode: Testing with sample logs...")
        test_logs = [
            "INFO: User login successful",
            "WARN: Failed login attempt for user admin",
            "CRITICAL: Suspicious process detected: powershell.exe",
            "WARN: Large data transfer to 192.168.1.100",
            "INFO: Application started normally"
        ]

        print("\nPredictions:")
        for log in test_logs:
            result = classifier.predict(log)
            print(f"\nLog: {log}")
            print(f"Category: {result['category']} (Confidence: {result['confidence']:.2%})")

if __name__ == "__main__":
    main()
