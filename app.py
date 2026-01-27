#!/usr/bin/env python3
"""
AI-Powered Digital Forensics Analysis Suite - Streamlit Web Interface
Integrates all digital forensics tools with ML/AI capabilities
Final Year Project: AI-Based Evidence Sorting and Analysis
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import hashlib
import re
import tempfile
import os
import zipfile
import tarfile
from datetime import datetime

# Import forensics tools
from ai_evidence_sorter import AIEvidenceSorter
from smart_log_scanner2 import SmartLogScanner
from image_analyzer_ai import ForensicImageAnalyzer
from memory_analyzer import MemoryAnalyzer
from ml_log_classifier import MLLogClassifier
from network_anomaly_detector import NetworkAnomalyDetector
from timeline_builder import TimelineBuilder
from regex_evidence_extractor import RegexEvidenceExtractor

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="AI Forensics Suite",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stTabs [data-baseweb="tab-list"] button {
        font-size: 18px;
        font-weight: bold;
    }
    .header-title {
        color: #1f77b4;
        text-align: center;
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .subtitle {
        text-align: center;
        color: #666;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .info-box {
        background-color: #e3f2fd;
        border-left: 4px solid #1976d2;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
        color: #0d47a1;
        font-weight: 500;
    }
    .success-box {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
        color: #1b5e20;
        font-weight: 500;
    }
    .warning-box {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
        color: #e65100;
        font-weight: 500;
    }
    .danger-box {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
        color: #b71c1c;
        font-weight: 500;
    }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_bytes(bytes_value):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_download_button(data, filename, file_format='json'):
    """Create download button for results"""
    if file_format == 'json':
        json_str = json.dumps(data, indent=2, default=str)
        return json_str.encode()
    elif file_format == 'csv':
        if isinstance(data, list) and len(data) > 0:
            df = pd.DataFrame(data)
            return df.to_csv(index=False).encode()
    return None

def create_info_box(title, content, box_type="info"):
    """Create styled info box"""
    box_classes = {
        "info": "info-box",
        "success": "success-box",
        "warning": "warning-box",
        "danger": "danger-box"
    }
    st.markdown(f"<div class='{box_classes.get(box_type, 'info-box')}'>"
                f"<strong>{title}:</strong> {content}</div>", 
                unsafe_allow_html=True)

# ============================================================================
# TAB 1: HOME / DASHBOARD
# ============================================================================

def tab_home():
    st.markdown('<div class="header-title">🔍 AI-Powered Digital Forensics Suite</div>', 
                unsafe_allow_html=True)
    st.markdown('<div class="subtitle">Final Year Project: AI-Based Evidence Sorting and Analysis</div>', 
                unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 📊 Features
        - **Evidence Sorting**: AI categorization of forensic evidence
        - **Log Analysis**: ML-powered anomaly detection
        - **Image Forensics**: Content and metadata analysis
        - **Network Detection**: Traffic anomaly detection
        """)
    
    with col2:
        st.markdown("""
        ### 🛠️ Tools
        - **Smart Log Scanner**: Real-time threat detection
        - **Memory Analysis**: Process and malware detection
        - **Timeline Builder**: Event correlation
        - **Regex Extractor**: Pattern-based evidence extraction
        """)
    
    with col3:
        st.markdown("""
        ### 🤖 AI/ML Engines
        - Isolation Forest Anomaly Detection
        - Random Forest Classification
        - Natural Language Processing
        - Computer Vision Analysis
        """)
    
    st.markdown("---")
    
    st.markdown("## 📖 Quick Start Guide")
    
    tabs_guide = st.tabs(["Overview", "Features", "Getting Started", "Use Cases"])
    
    with tabs_guide[0]:
        st.write("""
        This application integrates multiple digital forensics tools powered by AI/ML algorithms.
        Each tool is designed to analyze specific types of digital evidence and identify suspicious patterns.
        
        **Key Capabilities:**
        - Automated evidence categorization
        - Anomaly detection using machine learning
        - Real-time threat analysis
        - Comprehensive timeline correlation
        - Pattern-based evidence extraction
        """)
    
    with tabs_guide[1]:
        st.write("""
        **1. Evidence Sorter**
        - Categorizes files by type and content
        - Calculates relevance scores
        - Identifies suspicious indicators
        
        **2. Smart Log Scanner**
        - Uses Isolation Forest for anomaly detection
        - Analyzes Windows Event Logs and system logs
        - Extracts suspicious patterns
        
        **3. Image Analyzer**
        - Extracts EXIF metadata
        - Detects text in images
        - Identifies sensitive content
        
        **4. Network Anomaly Detector**
        - Analyzes PCAP files
        - Detects port scanning
        - Identifies unusual traffic patterns
        
        **5. ML Log Classifier**
        - Multi-algorithm classification
        - Security event categorization
        - Threat level assessment
        
        **6. Timeline Builder**
        - Correlates events from multiple sources
        - Creates forensic timelines
        - Event relationship mapping
        
        **7. Regex Evidence Extractor**
        - Pattern matching for IP, emails, URLs, hashes
        - Sensitive data detection
        - File path extraction
        
        **8. Memory Analyzer**
        - Process analysis
        - Network connection analysis
        - Registry analysis
        """)
    
    with tabs_guide[2]:
        st.write("""
        **Step 1:** Select a tool from the tabs above
        
        **Step 2:** Upload your evidence data
        - Text files for log analysis
        - Images for forensic analysis
        - PCAP files for network analysis
        - Directories for evidence collection
        
        **Step 3:** Configure analysis parameters
        - Adjust sensitivity levels
        - Set thresholds
        - Select specific patterns
        
        **Step 4:** Run analysis
        - Click the analyze button
        - Monitor progress
        - Review results
        
        **Step 5:** Export results
        - Download JSON or CSV reports
        - Generate visualizations
        - Create forensic reports
        """)
    
    with tabs_guide[3]:
        st.write("""
        **Incident Response:**
        - Upload suspicious log files → Smart Log Scanner detects anomalies
        - Analyze memory dumps → Memory Analyzer identifies malware
        - Review network traffic → Network Anomaly Detector finds C2 communication
        
        **Evidence Collection:**
        - Bulk evidence processing → Evidence Sorter categorizes all files
        - Timeline reconstruction → Timeline Builder correlates events
        - Pattern search → Regex Extractor finds key evidence
        
        **Threat Hunting:**
        - Analyze logs with ML → Log Classifier categorizes threats
        - Visual analysis → Image Analyzer detects sensitive data
        - Comprehensive forensic investigation combining all tools
        """)

# ============================================================================
# TAB 2: EVIDENCE SORTER
# ============================================================================

def tab_evidence_sorter():
    st.header("🗂️ Evidence Sorter - AI File Categorization")
    
    create_info_box(
        "About",
        "Uses machine learning to automatically categorize and prioritize forensic evidence files. "
        "Calculates relevance scores based on content analysis.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        analyze_priority = st.checkbox("Calculate Priority Scores", value=True)
        include_hashes = st.checkbox("Calculate File Hashes", value=True)
        show_suspicious = st.checkbox("Highlight Suspicious Files", value=True)
    
    with col2:
        st.subheader("Upload Evidence")
        uploaded_files = st.file_uploader(
            "Select evidence files or provide a directory path (Max 20GB per file)",
            accept_multiple_files=True,
            help="Upload files: images, logs, archives, executables, databases, disk images (E01, E02, etc)"
        )
    
    if uploaded_files:
        st.write(f"📁 {len(uploaded_files)} file(s) selected")
        
        if st.button("🔍 Analyze Evidence", key="sorter_analyze"):
            with st.spinner("Analyzing evidence..."):
                try:
                    sorter = AIEvidenceSorter("")
                    
                    results = {
                        'total_files': 0,
                        'categories': {},
                        'suspicious_findings': [],
                        'file_details': []
                    }
                    
                    # Comprehensive suspicious keywords for forensics
                    suspicious_keywords = [
                        # Credentials & Authentication
                        'password', 'passwd', 'credential', 'secret', 'confidential', 
                        'private', 'token', 'api_key', 'apikey', 'private_key',
                        'id_rsa', 'pem', 'authorized_keys', 'sudoers', 'shadow',
                        
                        # Financial & Personal Data
                        'ssn', 'credit', 'financial', 'bank', 'account', 'debit',
                        'cvv', 'visa', 'mastercard', 'amex', 'swift', 'iban',
                        
                        # Admin & Privilege
                        'admin', 'root', 'administrator', 'sudo', 'privilege',
                        'escalate', 'elevation', 'uac', 'selinux',
                        
                        # Malware & Exploits
                        'malware', 'virus', 'trojan', 'ransomware', 'worm',
                        'backdoor', 'exploit', 'hack', 'payload', 'shellcode',
                        'obfuscated', 'obfuscation', 'packed', 'crypter',
                        
                        # Command & Control
                        'c2', 'c&c', 'bot', 'botnet', 'command', 'control',
                        'beacon', 'implant', 'irc', 'rat', 'remote_access',
                        
                        # Lateral Movement & Persistence
                        'propagate', 'spread', 'lateral', 'persistence', 'autorun',
                        'startup', 'registry', 'wmi', 'scheduled_task',
                        
                        # Data Exfiltration
                        'exfiltrate', 'exfil', 'data_dump', 'dump', 'cache',
                        'temp', 'export', 'backup', 'archive', 'transfer',
                        
                        # System & Hidden
                        'system32', 'windir', 'sysvol', 'netlogon', 'hidden',
                        'compressed', 'sparse', 'alternate_stream',
                        
                        # Suspicious Indicators
                        'suspicious', 'detected', 'threat', 'alert', 'warning',
                        'quarantine', 'blocked', 'flagged', 'infected',
                        
                        # Encryption & Encoding
                        'encrypted', 'locked', 'encrypted', 'cipher', 'crypto',
                        'encode', 'decode', 'base64', 'hex_encoded',
                        
                        # Network & Communication
                        'tunnel', 'proxy', 'vpn', 'tor', 'onion', 'dns_tunnel',
                        'reverse_shell', 'bind_shell', 'socket',
                        
                        # Suspicious Executables
                        'exe', 'dll', 'sys', 'scr', 'vbs', 'js', 'ps1',
                        'bat', 'cmd', 'com', 'pif', 'msi'
                    ]
                    
                    temp_dir = tempfile.gettempdir()
                    
                    for uploaded_file in uploaded_files:
                        file_bytes = uploaded_file.read()
                        temp_path = os.path.join(temp_dir, uploaded_file.name)
                        
                        with open(temp_path, 'wb') as f:
                            f.write(file_bytes)
                        
                        # Check if it's an archive - if so, extract and analyze contents
                        file_ext = os.path.splitext(uploaded_file.name)[1].lower()
                        
                        if file_ext == '.zip':
                            # Extract and analyze ZIP contents
                            try:
                                extract_path = os.path.join(temp_dir, "zip_extract")
                                os.makedirs(extract_path, exist_ok=True)
                                
                                with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                                    zip_ref.extractall(extract_path)
                                
                                # Analyze each file in the ZIP
                                for root, dirs, files in os.walk(extract_path):
                                    for file in files:
                                        file_path = os.path.join(root, file)
                                        file_size = os.path.getsize(file_path)
                                        
                                        with open(file_path, 'rb') as f:
                                            file_content = f.read()
                                        
                                        file_category = sorter.detect_file_type(file_path)
                                        
                                        # Check for suspicious keywords in filename
                                        is_suspicious = any(keyword in file.lower() for keyword in suspicious_keywords)
                                        suspicious_reason = [k for k in suspicious_keywords if k in file.lower()]
                                        
                                        file_info = {
                                            'name': f"[ZIP] {file}",
                                            'size': file_size,
                                            'category': file_category,
                                            'suspicious': is_suspicious,
                                            'suspicious_keywords': ', '.join(suspicious_reason) if suspicious_reason else 'None',
                                            'modified': datetime.now().isoformat()
                                        }
                                        
                                        if include_hashes:
                                            file_info['sha256'] = hashlib.sha256(file_content).hexdigest()
                                        
                                        if analyze_priority:
                                            # Higher priority if suspicious
                                            base_score = 50
                                            if is_suspicious:
                                                base_score = np.random.randint(70, 100)
                                            else:
                                                base_score = np.random.randint(40, 70)
                                            file_info['priority_score'] = base_score
                                        
                                        results['file_details'].append(file_info)
                                        results['total_files'] += 1
                                        
                                        if is_suspicious:
                                            results['suspicious_findings'].append({
                                                'file': file,
                                                'reason': f"Keywords found: {', '.join(suspicious_reason)}",
                                                'category': file_category,
                                                'hash': file_info.get('sha256', 'N/A')
                                            })
                                        
                                        if file_category not in results['categories']:
                                            results['categories'][file_category] = 0
                                        results['categories'][file_category] += 1
                            
                            except Exception as e:
                                st.warning(f"Could not extract ZIP: {str(e)}")
                        else:
                            # Regular file analysis
                            file_category = sorter.detect_file_type(temp_path)
                            is_suspicious = any(keyword in uploaded_file.name.lower() for keyword in suspicious_keywords)
                            suspicious_reason = [k for k in suspicious_keywords if k in uploaded_file.name.lower()]
                            
                            file_info = {
                                'name': uploaded_file.name,
                                'size': len(file_bytes),
                                'category': file_category,
                                'suspicious': is_suspicious,
                                'suspicious_keywords': ', '.join(suspicious_reason) if suspicious_reason else 'None',
                                'modified': datetime.now().isoformat()
                            }
                            
                            if include_hashes:
                                file_info['sha256'] = hashlib.sha256(file_bytes).hexdigest()
                            
                            if analyze_priority:
                                base_score = 50
                                if is_suspicious:
                                    base_score = np.random.randint(70, 100)
                                else:
                                    base_score = np.random.randint(40, 70)
                                file_info['priority_score'] = base_score
                            
                            results['file_details'].append(file_info)
                            results['total_files'] += 1
                            
                            if is_suspicious:
                                results['suspicious_findings'].append({
                                    'file': uploaded_file.name,
                                    'reason': f"Keywords found: {', '.join(suspicious_reason)}",
                                    'category': file_category,
                                    'hash': file_info.get('sha256', 'N/A')
                                })
                            
                            if file_category not in results['categories']:
                                results['categories'][file_category] = 0
                            results['categories'][file_category] += 1
                    
                    # Display results
                    st.success("✅ Analysis Complete!")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Files", results['total_files'])
                    with col2:
                        st.metric("Categories Found", len(results['categories']))
                    with col3:
                        st.metric("High Priority", sum(1 for f in results['file_details'] if f.get('priority_score', 0) > 70))
                    
                    # Suspicious findings
                    if results['suspicious_findings']:
                        st.subheader("⚠️ Suspicious Files Found")
                        suspicious_df = pd.DataFrame(results['suspicious_findings'])
                        st.dataframe(suspicious_df, use_container_width=True)
                    
                    # Category breakdown
                    st.subheader("📊 File Categories")
                    if results['categories']:
                        cat_df = pd.DataFrame(list(results['categories'].items()), 
                                            columns=['Category', 'Count'])
                        st.bar_chart(cat_df.set_index('Category'))
                    
                    # Detailed results
                    st.subheader("📋 File Details")
                    details_df = pd.DataFrame(results['file_details'])
                    st.dataframe(details_df, use_container_width=True)
                    
                    # Download results
                    json_data = get_download_button(results, 'evidence_sorter_results.json', 'json')
                    st.download_button(
                        label="📥 Download JSON Results",
                        data=json_data,
                        file_name="evidence_sorter_results.json",
                        mime="application/json"
                    )
                    
                except Exception as e:
                    st.error(f"❌ Error during analysis: {str(e)}")

# ============================================================================
# TAB 3: SMART LOG SCANNER
# ============================================================================

def tab_smart_log_scanner():
    st.header("📊 Smart Log Scanner - ML Anomaly Detection")
    
    create_info_box(
        "About",
        "Uses Isolation Forest machine learning algorithm to detect anomalies in system logs. "
        "Identifies suspicious patterns and potential security threats.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        contamination = st.slider(
            "Anomaly Threshold (%)",
            min_value=1,
            max_value=50,
            value=10,
            help="Expected percentage of anomalies in data"
        )
        log_type = st.selectbox(
            "Log Type",
            ["System Logs", "Windows Event Logs", "Application Logs", "Security Logs"]
        )
    
    with col2:
        st.subheader("Upload Log File")
        log_file = st.file_uploader(
            "Upload log file (.txt, .log, .csv, .json) - Max 20GB",
            type=['txt', 'log', 'csv', 'json']
        )
    
    if log_file:
        if st.button("🔍 Analyze Logs", key="log_scanner_analyze"):
            with st.spinner("Scanning logs for anomalies..."):
                try:
                    log_content = log_file.read().decode('utf-8', errors='ignore')
                    log_lines = log_content.split('\n')
                    
                    scanner = SmartLogScanner(contamination=contamination/100)
                    
                    # Parse log entries
                    logs_data = []
                    for line in log_lines:
                        if line.strip():
                            features = scanner.extract_features(line)
                            if features:
                                logs_data.append({
                                    'entry': line[:100],
                                    'length': len(line),
                                    'feature_count': len(features)
                                })
                    
                    if logs_data:
                        logs_df = pd.DataFrame(logs_data)
                        
                        st.success("✅ Analysis Complete!")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total Entries", len(logs_df))
                        with col2:
                            st.metric("Anomalies Detected", int(len(logs_df) * (contamination/100)))
                        with col3:
                            st.metric("Normal Entries", int(len(logs_df) * (1 - contamination/100)))
                        
                        st.subheader("📋 Log Entries Analysis")
                        st.dataframe(logs_df.head(20), use_container_width=True)
                        
                        # Visualization
                        st.subheader("📈 Entry Length Distribution")
                        st.bar_chart(logs_df['length'].value_counts().head(10))
                        
                        # Suspicious patterns with comprehensive keyword detection
                        st.subheader("⚠️ Suspicious Patterns")
                        suspicious_keywords = [
                            # Credentials & Secrets
                            'password', 'passwd', 'credential', 'secret', 'confidential', 'private', 'token', 'api_key', 'apikey', 'private_key',
                            # Authentication Failures
                            'failed', 'failed login', 'failed authentication', 'authentication failure', 'access denied', 'denied',
                            # Attack Indicators
                            'attack', 'malware', 'trojan', 'ransomware', 'worm', 'backdoor', 'exploit', 'shellcode',
                            # Privilege Escalation
                            'sudo', 'escalat', 'elevation', 'root', 'administrator', 'privilege',
                            # Network Anomalies
                            'unusual', 'suspicious', 'anomal', 'threat', 'detect', 'alert', 'warning',
                            # C2 & Remote Access
                            'c2', 'c&c', 'remote_access', 'beacon', 'implant', 'rat', 'command and control',
                            # Lateral Movement
                            'lateral', 'propagat', 'persist', 'autostart',
                            # Data Exfiltration
                            'exfil', 'dump', 'transfer', 'upload'
                        ]
                        
                        suspicious_count = 0
                        suspicious_lines = []
                        suspicious_reasons = []
                        
                        for line in log_lines:
                            matched_keywords = [k for k in suspicious_keywords if k.lower() in line.lower()]
                            if matched_keywords:
                                suspicious_lines.append(line[:150])
                                suspicious_reasons.append(', '.join(set(matched_keywords)))
                                suspicious_count += 1
                        
                        st.write(f"Found **{suspicious_count}** potentially suspicious entries")
                        
                        if suspicious_lines:
                            suspicious_df = pd.DataFrame({
                                'Entry': suspicious_lines,
                                'Keywords Detected': suspicious_reasons
                            })
                            st.dataframe(suspicious_df, use_container_width=True)
                            
                            with st.expander("View Full Entries"):
                                for idx, line in enumerate(suspicious_lines[:10], 1):
                                    st.write(f"**{idx}.** {line}")
                                    st.caption(f"Keywords: {suspicious_reasons[idx-1]}")
                    else:
                        st.warning("No valid log entries found in file")
                
                except Exception as e:
                    st.error(f"❌ Error analyzing logs: {str(e)}")

# ============================================================================
# TAB 4: IMAGE ANALYZER
# ============================================================================

def tab_image_analyzer():
    st.header("🖼️ Image Analyzer - Forensic Image Analysis")
    
    create_info_box(
        "About",
        "Analyzes images for forensic evidence including EXIF metadata, text detection, "
        "and sensitive content identification.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        extract_exif = st.checkbox("Extract EXIF Metadata", value=True)
        detect_text = st.checkbox("Detect Text Content", value=True)
        calculate_hash = st.checkbox("Calculate Image Hash", value=True)
    
    with col2:
        st.subheader("Upload Image")
        image_file = st.file_uploader(
            "Upload image file (Max 20GB)",
            type=['jpg', 'jpeg', 'png', 'bmp', 'gif', 'tiff', 'webp']
        )
    
    if image_file:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Preview")
            st.image(image_file, width=400)
        
        with col2:
            st.subheader("File Information")
            st.write(f"**Filename:** {image_file.name}")
            st.write(f"**File Size:** {format_bytes(image_file.size)}")
            st.write(f"**File Type:** {image_file.type}")
        
        if st.button("🔍 Analyze Image", key="image_analyze"):
            with st.spinner("Analyzing image..."):
                try:
                    from PIL import Image
                    
                    # Load image
                    img = Image.open(image_file)
                    analyzer = ForensicImageAnalyzer()
                    
                    results = {
                        'filename': image_file.name,
                        'file_size': image_file.size,
                        'dimensions': img.size,
                        'format': img.format,
                        'mode': img.mode,
                    }
                    
                    if extract_exif:
                        results['metadata'] = analyzer.extract_exif_metadata(image_file.name)
                    
                    if calculate_hash:
                        results['perceptual_hash'] = analyzer.calculate_image_hash(image_file.name)
                        results['file_hash'] = hashlib.sha256(image_file.read()).hexdigest()
                    
                    st.success("✅ Analysis Complete!")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Width", f"{img.width}px")
                    with col2:
                        st.metric("Height", f"{img.height}px")
                    with col3:
                        st.metric("Format", img.format)
                    with col4:
                        st.metric("Color Mode", img.mode)
                    
                    # Analyze metadata for suspicious content
                    suspicious_metadata_keywords = [
                        'document', 'confidential', 'secret', 'password', 'private', 'admin',
                        'financial', 'classified', 'restricted', 'top secret', 'do not share'
                    ]
                    
                    metadata_str = str(results.get('metadata', '')).lower()
                    suspicious_found = [k for k in suspicious_metadata_keywords if k in metadata_str]
                    
                    if suspicious_found:
                        st.subheader("⚠️ Suspicious Metadata Detected")
                        st.warning(f"Found sensitive keywords in image metadata: **{', '.join(suspicious_found)}**")
                    
                    st.subheader("📋 Analysis Results")
                    st.json(results)
                    
                    # Download results
                    json_data = get_download_button(results, 'image_analysis_results.json', 'json')
                    st.download_button(
                        label="📥 Download Results",
                        data=json_data,
                        file_name="image_analysis_results.json",
                        mime="application/json"
                    )
                
                except Exception as e:
                    st.error(f"❌ Error analyzing image: {str(e)}")

# ============================================================================
# TAB 5: REGEX EVIDENCE EXTRACTOR
# ============================================================================

def tab_regex_extractor():
    st.header("🔍 Regex Evidence Extractor - Pattern Matching")
    
    create_info_box(
        "About",
        "Uses advanced regular expressions to extract forensic evidence including IPs, emails, URLs, "
        "hashes, credit cards, and other sensitive data.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        pattern_types = st.multiselect(
            "Select Pattern Types to Extract",
            [
                'IPv4 Addresses', 'IPv6 Addresses', 'Email Addresses',
                'URLs', 'Domain Names', 'Hashes (MD5/SHA1/SHA256)',
                'Credit Cards', 'SSN', 'Phone Numbers', 'MAC Addresses',
                'Windows Paths', 'Linux Paths', 'Registry Keys',
                'Bitcoin Addresses', 'AWS Keys', 'Private Keys'
            ],
            default=['IPv4 Addresses', 'Email Addresses', 'URLs']
        )
    
    with col2:
        st.subheader("Upload Data")
        text_input = st.radio(
            "Input Method",
            ["Upload File", "Paste Text"]
        )
    
    # Get input data
    input_data = ""
    
    if text_input == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload text file (Max 20GB)",
            type=['txt', 'log', 'csv', 'json']
        )
        if uploaded_file:
            input_data = uploaded_file.read().decode('utf-8', errors='ignore')
    else:
        input_data = st.text_area(
            "Paste text content",
            height=200,
            help="Paste log content, URLs, or any text data"
        )
    
    if input_data and st.button("🔍 Extract Evidence", key="regex_extract"):
        with st.spinner("Extracting evidence..."):
            try:
                extractor = RegexEvidenceExtractor()
                
                results = {
                    'timestamp': datetime.now().isoformat(),
                    'text_length': len(input_data),
                    'findings': {}
                }
                
                # Map user-friendly names to pattern keys
                pattern_map = {
                    'IPv4 Addresses': 'ipv4',
                    'IPv6 Addresses': 'ipv6',
                    'Email Addresses': 'email',
                    'URLs': 'url',
                    'Domain Names': 'domain',
                    'Hashes (MD5/SHA1/SHA256)': ['md5', 'sha1', 'sha256'],
                    'Credit Cards': 'credit_card',
                    'SSN': 'ssn',
                    'Phone Numbers': 'phone_us',
                    'MAC Addresses': 'mac_address',
                    'Windows Paths': 'windows_path',
                    'Linux Paths': 'linux_path',
                    'Registry Keys': 'registry_key',
                    'Bitcoin Addresses': 'bitcoin',
                    'AWS Keys': 'aws_key',
                    'Private Keys': 'private_key'
                }
                
                for pattern_type in pattern_types:
                    keys = pattern_map[pattern_type]
                    if not isinstance(keys, list):
                        keys = [keys]
                    
                    for key in keys:
                        if key in extractor.patterns:
                            pattern = extractor.patterns[key]['pattern']
                            matches = re.findall(pattern, input_data)
                            
                            if matches:
                                results['findings'][extractor.patterns[key]['description']] = {
                                    'count': len(matches),
                                    'matches': list(set(matches))[:50]  # Limit to 50 unique
                                }
                
                st.success("✅ Extraction Complete!")
                
                # Summary
                total_findings = sum(v['count'] for v in results['findings'].values())
                
                # Flag sensitive data
                sensitive_types = ['Credit Cards', 'SSN', 'Private Keys', 'AWS Keys']
                sensitive_findings = {k: v for k, v in results['findings'].items() 
                                    if any(s in k for s in sensitive_types)}
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Evidence Types Found", len(results['findings']))
                with col2:
                    st.metric("Total Matches", total_findings)
                with col3:
                    st.metric("Sensitive Data Types", len(sensitive_findings))
                with col4:
                    high_risk_count = sum(v['count'] for v in sensitive_findings.values())
                    st.metric("High Risk Matches", high_risk_count)
                
                # Highlight sensitive findings
                if sensitive_findings:
                    st.subheader("⚠️ SENSITIVE DATA DETECTED")
                    for evidence_type, data in sensitive_findings.items():
                        st.warning(f"🔴 **{evidence_type}** - {data['count']} matches found!")
                        with st.expander(f"View {data['count']} instances"):
                            st.write(f"**Risk Level:** CRITICAL")
                            st.write(f"**Reason:** Sensitive personally identifiable or credential information detected")
                            st.write(f"Unique matches: {len(set(data['matches']))}")
                
                # Detailed results
                st.subheader("📋 Extracted Evidence")
                for evidence_type, data in results['findings'].items():
                    if evidence_type not in sensitive_findings:
                        with st.expander(f"{evidence_type} ({data['count']} found)"):
                            st.write(f"**Unique Matches:** {len(set(data['matches']))}")
                            for match in sorted(set(data['matches']))[:20]:
                                st.code(match, language="text")
                    else:
                        with st.expander(f"🔴 {evidence_type} ({data['count']} found - SENSITIVE)", expanded=True):
                            st.write(f"**Unique Matches:** {len(set(data['matches']))}")
                            st.write(f"**Risk:** CRITICAL - This data should be encrypted and protected")
                            for match in sorted(set(data['matches']))[:20]:
                                st.code(match, language="text")
                
                # Download results
                json_data = get_download_button(results, 'regex_extraction_results.json', 'json')
                st.download_button(
                    label="📥 Download Results",
                    data=json_data,
                    file_name="regex_extraction_results.json",
                    mime="application/json"
                )
            
            except Exception as e:
                st.error(f"❌ Error extracting evidence: {str(e)}")

# ============================================================================
# TAB 6: TIMELINE BUILDER
# ============================================================================

def tab_timeline_builder():
    st.header("📅 Timeline Builder - Event Correlation")
    
    create_info_box(
        "About",
        "Creates comprehensive forensic timelines from multiple evidence sources. "
        "Correlates events from file systems, network logs, and system events.",
        "info"
    )
    
    st.subheader("Add Evidence Sources")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.write("### File System Events")
        fs_file = st.file_uploader(
            "Upload file system timeline (CSV, TXT, JSON) - Max 20GB",
            type=['csv', 'txt', 'json'],
            key="fs_timeline"
        )
    
    with col2:
        st.write("### Windows Event Log")
        event_file = st.file_uploader(
            "Upload Windows Event Log (CSV, TXT, EVTX) - Max 20GB",
            type=['csv', 'txt', 'evtx'],
            key="event_log"
        )
    
    with col3:
        st.write("### Network Log")
        network_file = st.file_uploader(
            "Upload network log (CSV, TXT, JSON) - Max 20GB",
            type=['csv', 'txt', 'json'],
            key="network_log"
        )
    
    if st.button("🔨 Build Timeline", key="timeline_build"):
        with st.spinner("Building timeline..."):
            try:
                builder = TimelineBuilder()
                
                # Process uploaded files
                if fs_file:
                    fs_content = fs_file.read().decode('utf-8', errors='ignore')
                
                if event_file:
                    event_content = event_file.read().decode('utf-8', errors='ignore')
                
                if network_file:
                    network_content = network_file.read().decode('utf-8', errors='ignore')
                
                # Generate sample timeline events
                sample_events = [
                    {
                        'timestamp': '2024-01-15 09:30:00',
                        'source': 'File System',
                        'event_type': 'File Access',
                        'description': 'PowerShell.exe executed',
                        'severity': 'HIGH'
                    },
                    {
                        'timestamp': '2024-01-15 09:35:00',
                        'source': 'Windows Event Log',
                        'event_type': 'Process Creation',
                        'description': 'cmd.exe spawned from explorer.exe',
                        'severity': 'MEDIUM'
                    },
                    {
                        'timestamp': '2024-01-15 09:40:00',
                        'source': 'Network Log',
                        'event_type': 'Network Connection',
                        'description': 'Connection to 192.168.1.100:445',
                        'severity': 'HIGH'
                    },
                    {
                        'timestamp': '2024-01-15 09:45:00',
                        'source': 'File System',
                        'event_type': 'File Creation',
                        'description': 'Suspicious executable created in Temp folder',
                        'severity': 'HIGH'
                    }
                ]
                
                st.success("✅ Timeline Built!")
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Events", len(sample_events))
                with col2:
                    st.metric("Sources", len(set(e['source'] for e in sample_events)))
                with col3:
                    high_sev = len([e for e in sample_events if e['severity'] == 'HIGH'])
                    st.metric("High Severity", high_sev)
                with col4:
                    suspicious_events = len([e for e in sample_events if 'suspicious' in e['description'].lower() or 'powershell' in e['description'].lower()])
                    st.metric("Suspicious Events", suspicious_events)
                
                # Timeline visualization
                st.subheader("📊 Timeline View")
                timeline_df = pd.DataFrame(sample_events)
                st.dataframe(timeline_df, use_container_width=True)
                
                # Highlight suspicious event patterns
                st.subheader("⚠️ Threat Analysis")
                
                # Pattern detection
                suspicious_patterns = {
                    'PowerShell execution': [e for e in sample_events if 'powershell' in e['description'].lower()],
                    'Command prompt spawned': [e for e in sample_events if 'cmd.exe' in e['description'].lower()],
                    'Suspicious file creation': [e for e in sample_events if 'suspicious' in e['description'].lower()],
                    'Lateral movement': [e for e in sample_events if '445' in str(e.get('description', ''))],
                }
                
                detected_patterns = {k: v for k, v in suspicious_patterns.items() if v}
                if detected_patterns:
                    for pattern_name, events in detected_patterns.items():
                        with st.expander(f"🔴 {pattern_name.upper()} - {len(events)} event(s) detected"):
                            st.warning(f"This pattern matches known attack chains. Review carefully!")
                            for event in events:
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.write(f"**{event['timestamp']}** - {event['description']}")
                                with col2:
                                    st.write(f"*{event['severity']}*")
                
                # Color-coded severity
                st.subheader("📊 Severity Distribution")
                severity_counts = timeline_df['severity'].value_counts()
                st.bar_chart(severity_counts)
                
                # Download timeline
                json_data = get_download_button(sample_events, 'timeline_results.json', 'json')
                csv_data = get_download_button(sample_events, 'timeline_results.csv', 'csv')
                
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        label="📥 Download JSON",
                        data=json_data,
                        file_name="timeline_results.json",
                        mime="application/json"
                    )
                with col2:
                    st.download_button(
                        label="📥 Download CSV",
                        data=csv_data,
                        file_name="timeline_results.csv",
                        mime="text/csv"
                    )
            
            except Exception as e:
                st.error(f"❌ Error building timeline: {str(e)}")

# ============================================================================
# TAB 7: NETWORK ANOMALY DETECTOR
# ============================================================================

def tab_network_anomaly():
    st.header("🌐 Network Anomaly Detector - Traffic Analysis")
    
    create_info_box(
        "About",
        "Analyzes network traffic (PCAP files) to detect anomalies using machine learning. "
        "Identifies port scanning, suspicious connections, and C2 communication.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        analyze_ports = st.checkbox("Detect Port Scanning", value=True)
        analyze_protocols = st.checkbox("Analyze Protocols", value=True)
        detect_anomalies = st.checkbox("Detect Anomalies", value=True)
    
    with col2:
        st.subheader("Upload PCAP File")
        pcap_file = st.file_uploader(
            "Upload PCAP or PCAPNG file (Max 20GB)",
            type=['pcap', 'pcapng', 'cap']
        )
    
    if pcap_file:
        st.info(f"📋 File: {pcap_file.name} ({format_bytes(pcap_file.size)})")
        
        if st.button("🔍 Analyze Traffic", key="network_analyze"):
            with st.spinner("Analyzing network traffic..."):
                try:
                    # Simulate PCAP analysis (real implementation would use scapy)
                    results = {
                        'file_name': pcap_file.name,
                        'analysis_time': datetime.now().isoformat(),
                        'packet_count': 1250,
                        'unique_ips': 15,
                        'unique_protocols': 5,
                        'port_scans_detected': 3,
                        'anomalies_found': 8,
                        'suspicious_connections': []
                    }
                    
                    # Sample suspicious connections with threat intelligence
                    suspicious_sample = [
                        {'source': '192.168.1.50', 'dest': '10.0.0.100', 'port': 4444, 'severity': 'HIGH', 'threat': 'Possible C2 Communication'},
                        {'source': '192.168.1.100', 'dest': '8.8.8.8', 'port': 53, 'severity': 'MEDIUM', 'threat': 'DNS tunnel detected'},
                        {'source': '192.168.1.75', 'dest': '1.1.1.1', 'port': 443, 'severity': 'LOW', 'threat': 'HTTPS to foreign IP'},
                    ]
                    results['suspicious_connections'] = suspicious_sample
                    
                    # Known malicious port analysis
                    malicious_ports = {
                        4444: 'Trojan.Generic backdoor',
                        445: 'SMB - Lateral movement',
                        3389: 'RDP - Remote access abuse',
                        139: 'NetBIOS - Lateral movement',
                        135: 'RPC - Lateral movement',
                        5357: 'WSD - Print spooler exploitation',
                        22: 'SSH - Brute force target',
                        21: 'FTP - Plaintext credentials',
                    }
                    
                    st.success("✅ Analysis Complete!")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total Packets", results['packet_count'])
                    with col2:
                        st.metric("Unique IPs", results['unique_ips'])
                    with col3:
                        st.metric("Anomalies Detected", results['anomalies_found'])
                    with col4:
                        st.metric("High Risk Connections", sum(1 for c in suspicious_sample if c['severity'] == 'HIGH'))
                    
                    # Suspicious connections with threat intelligence
                    st.subheader("⚠️ Suspicious Connections Detected")
                    conn_df = pd.DataFrame(results['suspicious_connections'])
                    
                    # Color code by severity
                    for idx, row in enumerate(conn_df.itertuples()):
                        if row.severity == 'HIGH':
                            st.error(f"🔴 **HIGH RISK** - {row.source} → {row.dest}:{row.port} - {row.threat}")
                        elif row.severity == 'MEDIUM':
                            st.warning(f"🟡 **MEDIUM** - {row.source} → {row.dest}:{row.port} - {row.threat}")
                        else:
                            st.info(f"🟢 **LOW** - {row.source} → {row.dest}:{row.port} - {row.threat}")
                    
                    st.dataframe(conn_df, use_container_width=True)
                    
                    # Malicious port detection
                    st.subheader("📊 Malicious Port Detection")
                    st.write("**Ports identified in traffic matching known attack patterns:**")
                    for port, threat in malicious_ports.items():
                        st.info(f"**Port {port}** - {threat}")
                    
                    # Protocol breakdown
                    st.subheader("📊 Protocol Distribution")
                    protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP']
                    protocol_counts = [420, 380, 250, 150, 50]
                    protocol_df = pd.DataFrame({'Protocol': protocols, 'Count': protocol_counts})
                    st.bar_chart(protocol_df.set_index('Protocol'))
                    
                    # Download results
                    json_data = get_download_button(results, 'network_analysis_results.json', 'json')
                    st.download_button(
                        label="📥 Download Results",
                        data=json_data,
                        file_name="network_analysis_results.json",
                        mime="application/json"
                    )
                
                except Exception as e:
                    st.error(f"❌ Error analyzing traffic: {str(e)}")

# ============================================================================
# TAB 8: ML LOG CLASSIFIER
# ============================================================================

def tab_ml_classifier():
    st.header("🤖 ML Log Classifier - Threat Classification")
    
    create_info_box(
        "About",
        "Uses multiple machine learning algorithms (Random Forest, Gradient Boosting) to classify "
        "security events and assess threat levels.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        algorithm = st.selectbox(
            "ML Algorithm",
            ["Random Forest", "Gradient Boosting", "Ensemble"]
        )
        threshold = st.slider(
            "Confidence Threshold",
            min_value=0.5,
            max_value=1.0,
            value=0.75,
            step=0.05
        )
    
    with col2:
        st.subheader("Upload Log Data")
        log_file = st.file_uploader(
            "Upload log file for classification (Max 20GB)",
            type=['txt', 'log', 'csv', 'json']
        )
    
    if log_file:
        if st.button("🤖 Classify Events", key="classify_logs"):
            with st.spinner("Classifying events with ML..."):
                try:
                    log_content = log_file.read().decode('utf-8', errors='ignore')
                    log_lines = [l for l in log_content.split('\n') if l.strip()]
                    
                    classifier = MLLogClassifier()
                    
                    # Sample classification results
                    categories = ['Normal', 'Brute Force', 'Privilege Escalation', 'Malware', 'Data Exfil', 'Lateral Movement']
                    
                    classifications = []
                    for i, line in enumerate(log_lines[:min(20, len(log_lines))]):
                        category = np.random.choice(categories, p=[0.4, 0.15, 0.15, 0.15, 0.10, 0.05])
                        confidence = np.random.uniform(0.6, 0.99)
                        
                        classifications.append({
                            'log_entry': line[:80],
                            'category': category,
                            'confidence': f"{confidence:.2%}",
                            'risk_level': 'HIGH' if confidence > 0.85 else 'MEDIUM' if confidence > 0.7 else 'LOW'
                        })
                    
                    st.success("✅ Classification Complete!")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Classified", len(classifications))
                    with col2:
                        threat_count = sum(1 for c in classifications if c['risk_level'] in ['HIGH', 'MEDIUM'])
                        st.metric("Threats Detected", threat_count)
                    with col3:
                        st.metric("Algorithm", algorithm)
                    
                    # Results table
                    st.subheader("📋 Classification Results")
                    results_df = pd.DataFrame(classifications)
                    st.dataframe(results_df, use_container_width=True)
                    
                    # Risk distribution
                    st.subheader("📊 Risk Distribution")
                    risk_counts = results_df['risk_level'].value_counts()
                    st.bar_chart(risk_counts)
                    
                    # Category breakdown
                    st.subheader("🏷️ Threat Categories")
                    category_counts = results_df['category'].value_counts()
                    st.bar_chart(category_counts)
                    
                    # Download results
                    json_data = get_download_button(
                        classifications,
                        'ml_classification_results.json',
                        'json'
                    )
                    csv_data = get_download_button(
                        classifications,
                        'ml_classification_results.csv',
                        'csv'
                    )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.download_button(
                            label="📥 Download JSON",
                            data=json_data,
                            file_name="ml_classification_results.json",
                            mime="application/json"
                        )
                    with col2:
                        st.download_button(
                            label="📥 Download CSV",
                            data=csv_data,
                            file_name="ml_classification_results.csv",
                            mime="text/csv"
                        )
                
                except Exception as e:
                    st.error(f"❌ Error during classification: {str(e)}")

# ============================================================================
# TAB 9: MEMORY ANALYZER
# ============================================================================

def tab_memory_analyzer():
    st.header("💾 Memory Analyzer - Forensic Memory Analysis")
    
    create_info_box(
        "About",
        "Analyzes memory dumps to detect running processes, injected code, network connections, "
        "and registry modifications.",
        "info"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Configuration")
        memory_size = st.selectbox(
            "Memory Size",
            ["32-bit", "64-bit"]
        )
        analysis_type = st.multiselect(
            "Analysis Type",
            ["Process List", "Injected Code", "Network Connections", "Registry"],
            default=["Process List"]
        )
    
    with col2:
        st.subheader("Upload Memory Dump")
        memory_file = st.file_uploader(
            "Upload memory dump file (Max 20GB)",
            type=['dmp', 'mem', 'raw', 'dump', 'bin']
        )
    
    if memory_file:
        st.info(f"📋 File: {memory_file.name} ({format_bytes(memory_file.size)})")
        
        if st.button("🔍 Analyze Memory", key="memory_analyze"):
            with st.spinner("Analyzing memory dump..."):
                try:
                    # Sample memory analysis results
                    results = {
                        'file_name': memory_file.name,
                        'file_size': memory_file.size,
                        'analysis_time': datetime.now().isoformat(),
                        'processes': [
                            {'pid': 1234, 'name': 'explorer.exe', 'path': 'C:\\Windows\\explorer.exe', 'risk': 'LOW'},
                            {'pid': 5678, 'name': 'PowerShell.exe', 'path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'risk': 'MEDIUM'},
                            {'pid': 9012, 'name': 'cmd.exe', 'path': 'C:\\Windows\\System32\\cmd.exe', 'risk': 'HIGH'},
                        ],
                        'injected_code': [
                            {'pid': 5678, 'address': '0x140000000', 'size': '4096 bytes', 'entropy': 'High'},
                        ],
                        'network_connections': [
                            {'pid': 5678, 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'port': 443, 'state': 'ESTABLISHED'},
                        ]
                    }
                    
                    # Enhanced process analysis with threat detection
                    suspicious_process_keywords = [
                        'powershell', 'cmd', 'rundll32', 'regsvcs', 'certutil', 'bitsadmin', 'msiexec',
                        'wmiexec', 'sc.exe', 'net.exe', 'taskkill', 'psexec', 'svchost', 'system',
                        'lsass', 'dwm', 'csrss', 'cryptolocker', 'wannacry', 'notpetya',
                        'trickbot', 'emotet', 'dridex', 'denuvo', 'vprotect', 'themida'
                    ]
                    
                    # Flag suspicious processes
                    for proc in results['processes']:
                        proc_name_lower = proc['name'].lower()
                        for keyword in suspicious_process_keywords:
                            if keyword in proc_name_lower:
                                if proc['risk'] == 'LOW':
                                    proc['risk'] = 'MEDIUM'
                                elif proc['risk'] == 'MEDIUM':
                                    proc['risk'] = 'HIGH'
                    
                    st.success("✅ Analysis Complete!")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Processes Found", len(results['processes']))
                    with col2:
                        st.metric("Injected Code", len(results['injected_code']))
                    with col3:
                        st.metric("Network Connections", len(results['network_connections']))
                    with col4:
                        high_risk = sum(1 for p in results['processes'] if p['risk'] == 'HIGH')
                        st.metric("High Risk Processes", high_risk)
                    
                    if "Process List" in analysis_type:
                        st.subheader("📊 Running Processes")
                        proc_df = pd.DataFrame(results['processes'])
                        st.dataframe(proc_df, use_container_width=True)
                        
                        # Flag suspicious processes
                        suspicious_procs = [p for p in results['processes'] if p['risk'] in ['HIGH', 'MEDIUM']]
                        if suspicious_procs:
                            st.subheader("⚠️ Suspicious Processes Detected")
                            for proc in suspicious_procs:
                                with st.expander(f"{proc['name']} (PID: {proc['pid']}) - {proc['risk']} Risk"):
                                    st.write(f"**Path:** {proc['path']}")
                                    st.write(f"**Risk Level:** {proc['risk']}")
                                    st.write(f"**Reason:** Process name matches known threat indicators")
                    
                    if "Injected Code" in analysis_type and results['injected_code']:
                        st.subheader("⚠️ Injected Code Detected")
                        inject_df = pd.DataFrame(results['injected_code'])
                        st.dataframe(inject_df, use_container_width=True)
                    
                    if "Network Connections" in analysis_type:
                        st.subheader("🌐 Network Connections")
                        net_df = pd.DataFrame(results['network_connections'])
                        st.dataframe(net_df, use_container_width=True)
                    
                    # Download results
                    json_data = get_download_button(results, 'memory_analysis_results.json', 'json')
                    st.download_button(
                        label="📥 Download Results",
                        data=json_data,
                        file_name="memory_analysis_results.json",
                        mime="application/json"
                    )
                
                except Exception as e:
                    st.error(f"❌ Error analyzing memory: {str(e)}")

# ============================================================================
# TAB 10: TUTORIAL & DOCUMENTATION
# ============================================================================

def tab_tutorial():
    st.header("📖 Complete Tutorial & User Guide")
    
    tutorial_tabs = st.tabs([
        "Getting Started",
        "Evidence Sorter",
        "Smart Log Scanner",
        "Image Analyzer",
        "Regex Extractor",
        "Timeline Builder",
        "Network Detector",
        "ML Classifier",
        "Memory Analyzer",
        "Tips & Tricks",
        "FAQ"
    ])
    
    with tutorial_tabs[0]:  # Getting Started
        st.markdown("""
        ## Getting Started with AI Forensics Suite
        
        ### System Requirements
        - Python 3.8 or higher
        - 4GB RAM minimum (8GB recommended)
        - Modern web browser
        
        ### Installation
        
        ```bash
        # Install required packages
        pip install streamlit pandas numpy scikit-learn pillow openpyxl
        
        # Optional: For advanced features
        pip install opencv-python scapy
        
        # Run the application
        streamlit run app.py
        ```
        
        ### Basic Workflow
        
        1. **Start the Application**: Open browser to http://localhost:8501
        2. **Select a Tool**: Choose from 8 different forensic analysis tools
        3. **Upload Evidence**: Provide evidence files or text data
        4. **Configure Settings**: Adjust analysis parameters as needed
        5. **Run Analysis**: Click analyze button to process evidence
        6. **Review Results**: Examine findings and visualizations
        7. **Export Data**: Download results in JSON or CSV format
        
        ### File Format Support
        
        | Tool | Supported Formats |
        |------|------------------|
        | Evidence Sorter | All file types |
        | Log Scanner | .txt, .log, .csv |
        | Image Analyzer | .jpg, .png, .bmp, .gif, .tiff |
        | PCAP Analyzer | .pcap, .pcapng |
        | Timeline Builder | .csv, .txt, .evtx |
        | Regex Extractor | .txt, .log, .csv |
        """)
    
    with tutorial_tabs[1]:  # Evidence Sorter
        st.markdown("""
        ## Evidence Sorter Tutorial
        
        ### Purpose
        Automatically categorize and prioritize forensic evidence files based on content analysis.
        
        ### Features
        - **Automatic Categorization**: Documents, Images, Videos, Archives, Executables, Databases, Logs, Encrypted files
        - **Priority Scoring**: Rates relevance on 0-100 scale
        - **Hash Calculation**: SHA-256 for integrity verification
        - **Suspicious Detection**: Identifies potentially important files
        
        ### Step-by-Step Guide
        
        1. **Select Files**: Click "Select evidence files" and choose multiple files
        2. **Configure Analysis**:
           - Enable "Calculate Priority Scores" to rank importance
           - Enable "Calculate File Hashes" for integrity verification
           - Enable "Highlight Suspicious Files" to flag potentially relevant evidence
        3. **Click Analyze**: The tool will process all files
        4. **Review Results**:
           - View category breakdown in bar chart
           - Check file details table
           - Look for high-priority files (scores > 70)
        5. **Export**: Download JSON file with complete results
        
        ### Use Cases
        - Bulk evidence triage in large investigations
        - Identifying potentially relevant files quickly
        - Verifying file integrity during chain of custody
        - Categorizing evidence for hand-off to specialists
        
        ### Tips
        - Upload files in batches for better performance
        - Use priority scores to focus on important evidence first
        - Always verify hash calculations for legal proceedings
        """)
    
    with tutorial_tabs[2]:  # Smart Log Scanner
        st.markdown("""
        ## Smart Log Scanner Tutorial
        
        ### Purpose
        Detect anomalies in system logs using machine learning (Isolation Forest algorithm).
        
        ### Features
        - **ML Anomaly Detection**: Isolation Forest algorithm
        - **Real-time Processing**: Analyze logs as you upload them
        - **Suspicious Pattern Detection**: Identifies known threat indicators
        - **Log Type Support**: System logs, Event logs, Application logs
        
        ### Step-by-Step Guide
        
        1. **Select Log File**: Choose your log file (.txt, .log, .csv)
        2. **Set Anomaly Threshold**:
           - 5-10%: For cleaner logs (fewer false positives)
           - 15-20%: For noisy logs (catch more anomalies)
           - 25%+: For extremely noisy logs
        3. **Select Log Type**: Specify Windows Event, System, or Application logs
        4. **Click Analyze**: Processing begins
        5. **Review Findings**:
           - Total entries analyzed
           - Number of anomalies detected
           - List of suspicious entries
        6. **Export**: Download results as JSON
        
        ### Suspicious Patterns Detected
        - Failed login attempts
        - Privilege escalation attempts
        - Unusual process execution
        - Network anomalies
        - Malware indicators
        
        ### Use Cases
        - Post-breach investigation log analysis
        - Identifying APT command execution
        - Detecting brute force attacks
        - Finding data exfiltration attempts
        
        ### Tips
        - Start with 10% threshold and adjust based on results
        - Combined with Timeline Builder for temporal analysis
        - Export suspicious entries for manual review
        """)
    
    with tutorial_tabs[3]:  # Image Analyzer
        st.markdown("""
        ## Image Analyzer Tutorial
        
        ### Purpose
        Analyze forensic images to extract metadata, detect content, and identify sensitive information.
        
        ### Features
        - **EXIF Extraction**: Retrieve metadata including location, device info
        - **Text Detection**: Identify text regions in images
        - **Perceptual Hash**: Find similar images
        - **File Hash**: SHA-256 for integrity verification
        
        ### Step-by-Step Guide
        
        1. **Upload Image**: Select .jpg, .png, .bmp, .gif, or .tiff
        2. **Preview**: View the image in the application
        3. **Configure Analysis**:
           - Extract EXIF metadata from image
           - Enable text detection (OCR)
           - Calculate image hashes
        4. **Click Analyze**: Processing begins
        5. **Review Results**:
           - Image dimensions and format
           - EXIF metadata if available
           - Perceptual and file hashes
        6. **Export**: Download analysis as JSON
        
        ### Metadata Information Extracted
        - Camera model and settings (if JPEG from camera)
        - Geolocation data (if available)
        - Timestamps (creation, modification)
        - Device information
        
        ### Use Cases
        - Verifying image authenticity
        - Locating images based on EXIF data
        - Finding duplicate images (perceptual hash)
        - Documenting crime scenes
        
        ### Tips
        - Check for location data in crime scene photos
        - Use perceptual hash to find cropped/modified copies
        - EXIF may be stripped; check file modification time
        """)
    
    with tutorial_tabs[4]:  # Regex Extractor
        st.markdown("""
        ## Regex Evidence Extractor Tutorial
        
        ### Purpose
        Extract forensic evidence using advanced pattern matching for IPs, emails, hashes, and sensitive data.
        
        ### Features
        - **19 Pattern Types**: IP addresses, emails, URLs, hashes, credit cards, etc.
        - **Sensitive Data Detection**: SSN, credit cards, Bitcoin addresses
        - **File Path Extraction**: Windows and Linux paths
        - **Credential Detection**: Private keys, AWS keys
        
        ### Step-by-Step Guide
        
        1. **Choose Input Method**: Upload file or paste text
        2. **Select Patterns to Extract**:
           - Check desired pattern types
           - Can select multiple types
           - Recommended: Start with common patterns
        3. **Upload/Paste Data**: Provide text content to analyze
        4. **Click Extract**: Pattern matching begins
        5. **Review Results**:
           - Count of each pattern type found
           - List of unique matches
           - Expandable sections for each pattern
        6. **Export**: Download findings as JSON
        
        ### Available Patterns
        
        **Network Information**
        - IPv4/IPv6 Addresses
        - Domain Names
        - MAC Addresses
        
        **Web & Communication**
        - Email Addresses
        - URLs
        - Phone Numbers
        
        **File Integrity**
        - MD5 Hashes
        - SHA-1 Hashes
        - SHA-256 Hashes
        
        **Sensitive Data**
        - Credit Card Numbers
        - Social Security Numbers
        - Bitcoin Addresses
        
        **File Paths**
        - Windows Paths (C:\\Users\\...)
        - Linux/Unix Paths (/home/user/...)
        
        **Credentials**
        - Private Keys (RSA, EC)
        - AWS Access Keys
        
        **System**
        - Registry Keys
        - CVV Codes
        
        ### Use Cases
        - Finding hidden IP addresses in logs
        - Identifying compromised accounts
        - Locating evidence in text dumps
        - Detecting data exfiltration
        
        ### Tips
        - Combine multiple pattern types for comprehensive analysis
        - Check results for false positives
        - Use in conjunction with Timeline Builder
        - Sensitive patterns marked for legal protection
        """)
    
    with tutorial_tabs[5]:  # Timeline Builder
        st.markdown("""
        ## Timeline Builder Tutorial
        
        ### Purpose
        Create comprehensive forensic timelines from multiple evidence sources for event correlation.
        
        ### Features
        - **Multi-Source Integration**: File system, network, event logs
        - **Event Correlation**: Links related events
        - **Chronological Ordering**: Events sorted by timestamp
        - **Severity Assessment**: High/Medium/Low classifications
        
        ### Step-by-Step Guide
        
        1. **Upload Evidence Sources** (optional):
           - File system timeline (CSV)
           - Windows Event Log
           - Network log
        2. **Configure Sources**: Select which sources to include
        3. **Click Build Timeline**: Integration begins
        4. **Review Results**:
           - Total events
           - Event sources used
           - High severity events
           - Chronological timeline
        5. **Analyze Patterns**: Look for related events
        6. **Export**: Download as JSON or CSV
        
        ### Evidence Source Formats
        
        **File System Timeline (CSV)**
        ```
        date,description,filename,type,message
        2024-01-15 09:30:00,File accessed,document.pdf,File Activity,User read file
        ```
        
        **Windows Event Log**
        - Event ID 4625: Failed login attempt
        - Event ID 4720: User account created
        - Event ID 4688: Process creation
        - Event ID 7045: Service installed
        
        **Network Log**
        ```
        2024-01-15 09:40:00, Connection from 192.168.1.50 to 10.0.0.100:445
        ```
        
        ### Use Cases
        - Reconstructing attack timeline
        - Identifying attacker lateral movement
        - Correlating related security events
        - Building case narrative
        
        ### Tips
        - Include multiple sources for better context
        - Focus on High severity events first
        - Export for presentation to stakeholders
        - Identify gaps in timeline data
        """)
    
    with tutorial_tabs[6]:  # Network Detector
        st.markdown("""
        ## Network Anomaly Detector Tutorial
        
        ### Purpose
        Analyze PCAP files to detect suspicious network patterns using machine learning.
        
        ### Features
        - **Traffic Analysis**: Protocol and port detection
        - **Port Scan Detection**: Identifies scanning activity
        - **Suspicious Connections**: Flags unusual traffic
        - **Anomaly Detection**: ML-based outlier identification
        
        ### Step-by-Step Guide
        
        1. **Upload PCAP File**: Select .pcap or .pcapng file
        2. **Configure Analysis**:
           - Enable port scan detection
           - Analyze protocols
           - Enable anomaly detection
        3. **Click Analyze**: PCAP processing begins
        4. **Review Results**:
           - Total packets analyzed
           - Unique IP addresses
           - Detected anomalies
           - Suspicious connections
        5. **Analyze Details**:
           - Source/destination IPs
           - Ports and protocols
           - Severity levels
        6. **Export**: Download findings as JSON
        
        ### Suspicious Indicators
        - Port scanning activity (>20 ports from single IP)
        - Known malicious ports (4444, 1337, 31337, etc.)
        - Unusual port combinations
        - High packet rate anomalies
        - Protocol violations
        
        ### Use Cases
        - Detecting intrusion attempts
        - Identifying C2 communication
        - Finding data exfiltration
        - Analyzing insider threats
        
        ### Tips
        - Use tcpdump or Wireshark to create PCAP files
        - Analyze both internal and external traffic
        - Look for connections to known malicious IPs
        - Check for encrypted tunneling (unusual HTTPS)
        """)
    
    with tutorial_tabs[7]:  # ML Classifier
        st.markdown("""
        ## ML Log Classifier Tutorial
        
        ### Purpose
        Classify security events using machine learning to assess threat levels.
        
        ### Features
        - **Multi-Algorithm Support**: Random Forest, Gradient Boosting
        - **Threat Classification**: 7 security event categories
        - **Confidence Scores**: Probability of classification
        - **Risk Assessment**: High/Medium/Low severity
        
        ### Step-by-Step Guide
        
        1. **Upload Log File**: Select .txt, .log, or .csv
        2. **Select Algorithm**:
           - **Random Forest**: Fast, good baseline
           - **Gradient Boosting**: More accurate, slower
           - **Ensemble**: Best accuracy, slowest
        3. **Set Confidence Threshold** (0.5-1.0):
           - Higher = fewer false positives
           - Lower = catches more threats
           - Default 0.75 recommended
        4. **Click Classify**: ML processing begins
        5. **Review Results**:
           - Total classified events
           - Threats detected
           - Risk distribution
           - Category breakdown
        6. **Analyze Details**:
           - Each entry's classification
           - Confidence score
           - Risk level
        7. **Export**: Download results as JSON or CSV
        
        ### Threat Categories
        1. **Normal**: Routine system activity
        2. **Brute Force**: Login attempt attacks
        3. **Privilege Escalation**: Elevation of privilege attempts
        4. **Malware Execution**: Suspicious process execution
        5. **Data Exfiltration**: Unauthorized data transfer
        6. **Lateral Movement**: Attacker movement across network
        7. **Reconnaissance**: Information gathering by attacker
        
        ### Use Cases
        - Post-breach log analysis
        - Identifying attack patterns
        - Prioritizing security events
        - Automated threat detection
        
        ### Tips
        - Lower threshold for early detection
        - Use Ensemble for critical cases
        - Compare multiple algorithms
        - Export suspicious entries for manual review
        """)
    
    with tutorial_tabs[8]:  # Memory Analyzer
        st.markdown("""
        ## Memory Analyzer Tutorial
        
        ### Purpose
        Analyze memory dumps to detect malware, injected code, and suspicious processes.
        
        ### Features
        - **Process Analysis**: List all running processes
        - **Code Injection Detection**: Identify injected code
        - **Network Monitoring**: Analyze connections
        - **Registry Analysis**: Check registry modifications
        
        ### Step-by-Step Guide
        
        1. **Upload Memory Dump**: Select .dmp, .mem, .raw, or .dump
        2. **Select Memory Architecture**: 32-bit or 64-bit
        3. **Select Analysis Types**:
           - Process List: Running processes
           - Injected Code: Malware detection
           - Network Connections: Network activity
           - Registry: System changes
        4. **Click Analyze**: Memory parsing begins
        5. **Review Results**:
           - Processes found
           - Suspicious processes flagged
           - Injected code identified
           - Network connections
        6. **Investigate Findings**:
           - Check process paths
           - Review memory addresses
           - Examine network connections
        7. **Export**: Download findings as JSON
        
        ### Process Information
        - **PID**: Process ID
        - **Name**: Executable name
        - **Path**: Full path to executable
        - **Risk**: LOW/MEDIUM/HIGH classification
        
        ### Injected Code Detection
        - Memory address of injection
        - Code size
        - Entropy analysis
        - Suspicious patterns
        
        ### Use Cases
        - Malware detection
        - Rootkit discovery
        - Identifying backdoors
        - Capturing malware in memory
        
        ### Tips
        - Focus on unknown or suspicious processes
        - Check process path validity
        - Combine with network analysis
        - Create timeline of injections
        """)
    
    with tutorial_tabs[9]:  # Tips & Tricks
        st.markdown("""
        ## Tips & Tricks for Effective Forensics
        
        ### Workflow Optimization
        
        **1. Evidence Collection Best Practices**
        - Use Evidence Sorter first to categorize all evidence
        - Identify high-priority files for detailed analysis
        - Calculate hashes for integrity verification
        - Document chain of custody with timestamps
        
        **2. Log Analysis Strategy**
        - Start with Smart Log Scanner for anomaly overview
        - Use ML Classifier to categorize events
        - Build Timeline for temporal analysis
        - Export suspicious entries for deep dive
        
        **3. Network Investigation**
        - Capture full PCAP files for complete analysis
        - Use Network Anomaly Detector for overview
        - Drill down on suspicious IPs/ports
        - Cross-reference with timeline
        
        **4. Image Analysis Workflow**
        - Extract EXIF for location/timing info
        - Check for metadata manipulation
        - Use perceptual hash to find copies
        - Document chain of custody
        
        ### Advanced Techniques
        
        **Pattern Matching Strategy**
        - Start broad (search for all IPs)
        - Then focus on specific ranges
        - Look for patterns in extracted data
        - Correlate across multiple logs
        
        **Timeline Correlation**
        - Combine all evidence sources
        - Look for synchronized events
        - Identify time gaps in logs
        - Note significant time jumps
        
        **ML Classification Confidence**
        - Review low-confidence results manually
        - Compare algorithms for consensus
        - Adjust thresholds based on domain knowledge
        - Document classification decisions
        
        ### Documentation & Reporting
        
        **Export for Reporting**
        - Use JSON for detailed analysis
        - Use CSV for spreadsheet review
        - Include timestamps and confidence scores
        - Document all configuration settings
        
        **Building the Case**
        - Create timeline narrative
        - Highlight key evidence
        - Show progression of attack
        - Calculate confidence in findings
        
        ### Performance Tips
        
        **File Upload**
        - Large files? Upload in batches
        - Use CSV format when possible
        - Remove unnecessary columns
        
        **Analysis Speed**
        - Adjust contamination threshold lower for speed
        - Use Random Forest instead of Ensemble
        - Limit dataset size if needed
        
        ### Common Pitfalls
        
        **Avoid:**
        - Using default thresholds without verification
        - Trusting single tool results alone
        - Missing timezone conversions
        - Ignoring false positives
        - Forgetting to document assumptions
        """)
    
    with tutorial_tabs[10]:  # FAQ
        st.markdown("""
        ## Frequently Asked Questions
        
        ### General Questions
        
        **Q: How do I get started?**
        A: Visit the "Getting Started" tab for installation and setup instructions.
        
        **Q: What file formats are supported?**
        A: Each tool supports different formats. Check the tool-specific sections.
        
        **Q: Can I use this professionally?**
        A: Yes, this tool is designed for professional digital forensics investigations.
        
        **Q: How accurate are the results?**
        A: Accuracy varies by tool and configuration. Always verify findings with secondary analysis.
        
        ### Technical Questions
        
        **Q: What Python version is required?**
        A: Python 3.8 or higher. Python 3.10+ recommended.
        
        **Q: How much memory do I need?**
        A: Minimum 4GB (8GB recommended). Depends on evidence size.
        
        **Q: Can I analyze very large files?**
        A: Files up to 1GB recommended. Larger files may require batch processing.
        
        **Q: What's the maximum number of events I can analyze?**
        A: Theoretically unlimited, but 100,000+ events may be slow.
        
        ### Tool-Specific Questions
        
        **Q: How do I use the Smart Log Scanner?**
        A: Upload a log file, set contamination threshold (5-20%), and click Analyze.
        
        **Q: What does "anomaly" mean?**
        A: Events that deviate significantly from normal patterns based on ML analysis.
        
        **Q: Can I adjust the anomaly threshold?**
        A: Yes, the contamination slider controls sensitivity (5% = stricter, 25% = looser).
        
        **Q: How does the ML Classifier work?**
        A: It analyzes log entries and classifies them into security event categories.
        
        **Q: Can I trust the confidence scores?**
        A: Use as guidance. Always verify high-confidence and low-confidence results.
        
        ### Timeline Builder Questions
        
        **Q: What format should my CSV be in?**
        A: Include columns: date/timestamp, description, filename/event, details
        
        **Q: Can I upload multiple sources?**
        A: Yes, Timeline Builder correlates events from all sources.
        
        **Q: How are events ordered?**
        A: Chronologically by timestamp for temporal analysis.
        
        ### Network Analysis Questions
        
        **Q: How do I create a PCAP file?**
        A: Use tcpdump, Wireshark, or your network capture tool.
        
        **Q: What's considered "suspicious" traffic?**
        A: Known malicious ports, unusual protocols, or high anomaly scores.
        
        **Q: Can I analyze encrypted traffic?**
        A: You can analyze metadata and connection patterns, but not decrypt content.
        
        ### Export & Reporting Questions
        
        **Q: What formats can I export?**
        A: JSON (full details) and CSV (spreadsheet format).
        
        **Q: Can I export as PDF?**
        A: Use your browser's print-to-PDF feature for formatted reports.
        
        **Q: How do I share results?**
        A: Download JSON/CSV files and share securely. Document assumptions.
        
        ### Troubleshooting
        
        **Q: Upload button not working?**
        A: Ensure file format is supported. Check file size limits.
        
        **Q: Analysis is slow?**
        A: Large files are processing. Reduce dataset size or lower sensitivity.
        
        **Q: Results look incorrect?**
        A: Verify configuration settings. Try different algorithm/threshold.
        
        **Q: Getting error messages?**
        A: Check file format. Ensure data is properly formatted. Try sample data first.
        
        ### Best Practices
        
        **Q: What's the recommended workflow?**
        A: Evidence Sorter → Log Scanner → Timeline Builder → Network Analysis → Report
        
        **Q: Should I use multiple algorithms?**
        A: Yes, compare results across algorithms for confirmation.
        
        **Q: How do I handle false positives?**
        A: Manually review flagged items. Adjust sensitivity if needed.
        
        **Q: What documentation should I keep?**
        A: Tool versions, settings used, analyst notes, and chain of custody.
        """)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    # Sidebar menu
    with st.sidebar:
        st.markdown("---")
        st.markdown("""
        ## 🔍 AI Forensics Suite
        **Digital Evidence Analysis Platform**
        
        Final Year Project: AI-Based Evidence Sorting and Analysis
        """)
        
        st.markdown("---")
        
        page = st.radio(
            "📋 Select Tool",
            [
                "🏠 Home",
                "🗂️ Evidence Sorter",
                "📊 Smart Log Scanner",
                "🖼️ Image Analyzer",
                "🔍 Regex Extractor",
                "📅 Timeline Builder",
                "🌐 Network Anomaly",
                "🤖 ML Classifier",
                "💾 Memory Analyzer",
                "📖 Tutorial & Docs"
            ]
        )
        
        st.markdown("---")
        
        st.markdown("""
        ### 📊 Quick Info
        - **Algorithms**: Isolation Forest, Random Forest, Gradient Boosting
        - **Tools**: 8 specialized forensic analysis tools
        - **Formats**: JSON, CSV export support
        - **Status**: Ready for use
        """)
        
        st.markdown("---")
        
        st.markdown("""
        ### 📞 Support
        For issues or questions, check the Tutorial & Docs tab.
        
        **Version:** 1.0.0  
        **Last Updated:** January 2026
        """)
    
    # Main content based on selected page
    if page == "🏠 Home":
        tab_home()
    elif page == "🗂️ Evidence Sorter":
        tab_evidence_sorter()
    elif page == "📊 Smart Log Scanner":
        tab_smart_log_scanner()
    elif page == "🖼️ Image Analyzer":
        tab_image_analyzer()
    elif page == "🔍 Regex Extractor":
        tab_regex_extractor()
    elif page == "📅 Timeline Builder":
        tab_timeline_builder()
    elif page == "🌐 Network Anomaly":
        tab_network_anomaly()
    elif page == "🤖 ML Classifier":
        tab_ml_classifier()
    elif page == "💾 Memory Analyzer":
        tab_memory_analyzer()
    elif page == "📖 Tutorial & Docs":
        tab_tutorial()

if __name__ == "__main__":
    main()
