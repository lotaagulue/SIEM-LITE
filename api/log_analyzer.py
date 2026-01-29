import re

class LogAnalyzer:
    """
    Analyzes log events for security threats and anomalies.
    """
    
    def __init__(self):
        # Common attack patterns based on README features
        self.patterns = {
            "SQL Injection": [
                r"OR '1'='1", r"UNION SELECT", r"admin' --", r"SLEEP\(", 
                r"DROP TABLE", r"information_schema"
            ],
            "XSS": [
                r"<script>", r"javascript:", r"onerror=", r"onload=", 
                r"document\.cookie", r"alert\("
            ],
            "Path Traversal": [
                r"\.\./", r"/etc/passwd", r"c:\\windows", r"%2e%2e%2f"
            ],
            "Command Injection": [
                r"; cat", r"\| ls", r"&&", r"\$\(", r"eval\("
            ],
            "Log4Shell": [
                r"\$\{jndi:"
            ]
        }

    def analyze_event(self, data):
        """
        Analyze a single log event for anomalies.
        """
        score = 0.0
        detected_attacks = []
        risk_factors = []
        
        message = str(data.get('message', ''))
        
        # Check for attack patterns
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    score += 0.4
                    detected_attacks.append(attack_type)
                    # Break inner loop to avoid duplicate counts for same attack type
                    break
        
        # Check severity
        if data.get('severity') in ['critical', 'high']:
            score += 0.3
            risk_factors.append(f"High severity event: {data.get('severity')}")
            
        return {
            "is_anomaly": score >= 0.5 or len(detected_attacks) > 0,
            "anomaly_score": min(score, 1.0),
            "detected_attacks": detected_attacks,
            "risk_factors": risk_factors
        }