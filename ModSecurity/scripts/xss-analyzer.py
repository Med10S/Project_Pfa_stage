#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyseur XSS personnalisé pour Wazuh
Créé par Med10S - 2025-08-08
"""

import json
import re
import sys
import time
import requests
from datetime import datetime
import base64
import urllib.parse

# Configuration
WEBHOOK_URL = "http://192.168.15.3:5678/webhook/wazuh-xss-analysis"
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script[^>]*>',
    r'javascript:\s*[^;]+',
    r'on\w+\s*=\s*["\'][^"\']*["\']',
    r'<iframe[^>]+src\s*=\s*["\']javascript:',
    r'<img[^>]+onerror\s*=',
    r'document\.(write|cookie|location)',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'<svg[^>]*onload\s*=',
    r'<body[^>]*onload\s*=',
    r'<input[^>]*onfocus\s*='
]

# Patterns pour bypasses courants
BYPASS_PATTERNS = [
    r'&#x[0-9a-fA-F]+;',  # Hex encoding
    r'&#[0-9]+;',         # Decimal encoding
    r'%[0-9a-fA-F]{2}',   # URL encoding
    r'\\\w+',             # Backslash encoding
    r'String\.fromCharCode',
    r'unescape\s*\(',
    r'decodeURI\s*\('
]

class XSSAnalyzer:
    def __init__(self):
        self.patterns_compiled = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                for pattern in XSS_PATTERNS]
        self.bypass_patterns = [re.compile(pattern, re.IGNORECASE) 
                               for pattern in BYPASS_PATTERNS]
    
    def decode_payload(self, payload):
        """Décode les différents encodages utilisés pour bypasser les filtres"""
        decoded_variants = [payload]
        
        try:
            # URL decode
            url_decoded = urllib.parse.unquote(payload)
            if url_decoded != payload:
                decoded_variants.append(url_decoded)
            
            # HTML entities decode
            import html
            html_decoded = html.unescape(payload)
            if html_decoded != payload:
                decoded_variants.append(html_decoded)
            
            # Base64 decode (si c'est du base64 valide)
            try:
                if len(payload) % 4 == 0:
                    base64_decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                    if base64_decoded and base64_decoded != payload:
                        decoded_variants.append(base64_decoded)
            except:
                pass
                
        except Exception as e:
            print(f"Erreur lors du décodage: {e}", file=sys.stderr)
        
        return decoded_variants
    
    def analyze_xss_payload(self, payload):
        """Analyse un payload pour détecter les tentatives XSS"""
        if not payload:
            return None
        
        # Décodage du payload
        payload_variants = self.decode_payload(payload)
        
        detection_results = {
            "xss_detected": False,
            "bypass_detected": False,
            "patterns_matched": [],
            "bypass_techniques": [],
            "risk_score": 0,
            "payload_variants": payload_variants
        }
        
        # Analyse de chaque variante
        for variant in payload_variants:
            # Détection XSS
            for i, pattern in enumerate(self.patterns_compiled):
                if pattern.search(variant):
                    detection_results["xss_detected"] = True
                    detection_results["patterns_matched"].append({
                        "pattern_id": i,
                        "pattern": XSS_PATTERNS[i],
                        "match": pattern.search(variant).group(0)[:100]
                    })
                    detection_results["risk_score"] += 20
            
            # Détection de bypasses
            for i, bypass_pattern in enumerate(self.bypass_patterns):
                if bypass_pattern.search(variant):
                    detection_results["bypass_detected"] = True
                    detection_results["bypass_techniques"].append({
                        "technique_id": i,
                        "technique": BYPASS_PATTERNS[i],
                        "match": bypass_pattern.search(variant).group(0)[:50]
                    })
                    detection_results["risk_score"] += 10
        
        # Classification du risque
        if detection_results["risk_score"] >= 50:
            detection_results["risk_level"] = "CRITICAL"
        elif detection_results["risk_score"] >= 30:
            detection_results["risk_level"] = "HIGH"
        elif detection_results["risk_score"] >= 15:
            detection_results["risk_level"] = "MEDIUM"
        else:
            detection_results["risk_level"] = "LOW"
        
        return detection_results if detection_results["xss_detected"] else None
    
    def send_analysis_webhook(self, analysis_result, original_log):
        """Envoie les résultats d'analyse vers n8n"""
        webhook_payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "Wazuh-XSS-Analyzer",
            "alert_type": "Advanced_XSS_Analysis",
            "severity": analysis_result.get("risk_level", "LOW"),
            "analysis": analysis_result,
            "original_log": original_log,
            "analyst": "Med10S",
            "detection_engine": "Custom-Python-Analyzer"
        }
        
        try:
            response = requests.post(
                WEBHOOK_URL,
                json=webhook_payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Source": "Wazuh-Custom-Analyzer",
                    "X-Alert-Type": "XSS-Analysis"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ Analyse XSS envoyée vers n8n")
            else:
                print(f"❌ Erreur webhook: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Erreur envoi analyse: {e}", file=sys.stderr)

def main():
    """Point d'entrée principal pour Wazuh"""
    analyzer = XSSAnalyzer()
    
    # Lecture depuis stdin (Wazuh passe les données via stdin)
    try:
        input_data = sys.stdin.read().strip()
        if not input_data:
            return
        
        # Tentative de parsing JSON (logs structurés)
        try:
            log_data = json.loads(input_data)
            payload = None
            
            # Extraction du payload selon le format du log
            if 'transaction' in log_data and 'request' in log_data['transaction']:
                payload = log_data['transaction']['request'].get('body') or \
                         log_data['transaction']['request'].get('uri')
            elif 'data' in log_data:
                payload = log_data['data']
            else:
                payload = input_data
                
        except json.JSONDecodeError:
            # Si ce n'est pas du JSON, traiter comme texte brut
            payload = input_data
            log_data = {"raw_message": input_data}
        
        # Analyse XSS
        if payload:
            analysis_result = analyzer.analyze_xss_payload(payload)
            
            if analysis_result:
                print(f"🚨 XSS DÉTECTÉ - Niveau: {analysis_result['risk_level']}")
                print(f"📊 Score de risque: {analysis_result['risk_score']}")
                print(f"🎯 Patterns détectés: {len(analysis_result['patterns_matched'])}")
                
                # Envoi vers n8n si webhook configuré
                if WEBHOOK_URL != "http://192.168.15.3:5678/webhook/wazuh-xss-analysis":
                    analyzer.send_analysis_webhook(analysis_result, log_data)
                
                # Sortie pour Wazuh (format JSON)
                wazuh_output = {
                    "xss_analysis": analysis_result,
                    "timestamp": datetime.utcnow().isoformat(),
                    "analyzer": "custom-xss-detector"
                }
                print(json.dumps(wazuh_output))
            
    except Exception as e:
        print(f"❌ Erreur dans l'analyseur XSS: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())