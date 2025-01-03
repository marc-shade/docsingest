#!/usr/bin/env python3
"""
Demonstration script for PII Detection and Redaction.

This script showcases the capabilities of the PIIDetector class in detecting 
and redacting various types of Personally Identifiable Information (PII).
"""

import sys
import os

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from docsingest.pii_detector import PIIDetector, analyze_document_compliance

def main():
    # Initialize PII Detector
    detector = PIIDetector()

    # Sample text with various PII types
    sample_texts = [
        "John Doe's email is john.doe@example.com and phone is 555-123-4567.",
        "Credit card: 4111-1111-1111-1111 belongs to Jane Smith.",
        "Social Security Number: 123-45-6789 for employee records.",
        "Mixed document with some sensitive info: Alice Johnson works at Tech Corp, her SSN is 987-65-4321 and email alice.j@techcorp.com.",
    ]

    print("=== PII DETECTION AND REDACTION DEMO ===\n")

    # Demonstrate detection and redaction for each text
    for idx, text in enumerate(sample_texts, 1):
        print(f"Document {idx}:")
        print(f"Original Text: {text}")
        
        # Detect PII
        detection_result = detector.detect(text)
        print("\nPII Detection Results:")
        print(f"PII Detected: {detection_result['pii_detected']}")
        print(f"PII Details: {detection_result['pii_details']}")
        print(f"Risk Score: {detection_result['risk_score']}")
        print("Recommended Actions:", ", ".join(detection_result['recommended_actions']))
        
        # Redact PII
        redacted_text = detector.redact(text)
        print(f"\nRedacted Text: {redacted_text}\n")
        print("-" * 50 + "\n")

    # Demonstrate document compliance analysis
    print("=== DOCUMENT COMPLIANCE ANALYSIS ===")
    
    # Create a temporary document with PII
    test_doc_path = "/tmp/pii_test_document.txt"
    with open(test_doc_path, "w") as f:
        f.write("Confidential: Employee John Smith, SSN 123-45-6789, works at Acme Corp. Contact email: john.smith@acmecorp.com")
    
    try:
        # Analyze document compliance
        compliance_report = analyze_document_compliance(test_doc_path)
        
        print("\nDocument Compliance Report:")
        print(f"PII Detected: {compliance_report['pii_detected']}")
        print(f"Risk Score: {compliance_report['risk_score']}")
        print("Recommended Actions:", ", ".join(compliance_report['recommended_actions']))
    
    finally:
        # Clean up temporary file
        os.remove(test_doc_path)

if __name__ == "__main__":
    main()
