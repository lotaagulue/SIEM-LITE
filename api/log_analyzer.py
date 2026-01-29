"""
SIEM Lite - Log Analysis Engine
Analyzes logs for suspicious patterns and anomalies
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

class LogAnalyzer:
    """Analyzes security events for suspicious patterns"""
    
    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s+\d+\s*=\s*\d+)",
        r"(\';\s*drop\s+table)",
        r"(--\s*$)",
        r"(/\*.*\*/)",
        r"(xp_cmdshell)",
        r"(exec\s*\()",
    ]
    
    XSS_PATTERNS = [
        r"(<script[^>]*>.*?</script>)",
        r"(javascript:)",
        r"(on\w+\s*=)",
        r"(<iframe)",
        r"(eval\s*\()",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"(\.\./)+",
        r"(\.\.\\)+",
        r"(%2e%2e/)",
        r"(%252e%252e)",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(;\s*cat\s+)",
        r"(;\s*ls\s+)",
        r"(\|\s*nc\s+)",
        r"(&&\s*\w+)",
        r"(`.*`)",
        r"(\$\(.*\))",
    ]
    
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': self.SQL_INJECTION_PATTERNS,
            'xss': self.XSS_PATTERNS,
            'path_traversal': self.PATH_TRAVERSAL_PATTERNS,
            'command_injection': self.COMMAND_INJECTION_PATTERNS,
        }
        
    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single event for suspicious patterns"""
        analysis_result = {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'detected_attacks': [],
            'risk_factors': [],
        }
        
        message = event.get('message', '')
        user_agent = event.get('user_agent', '')
        
        # Check for attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    analysis_result['detected_attacks'].append(attack_type)
                    analysis_result['anomaly_score'] += 0.3
                    break
        
        # Check for suspicious user agents
        suspicious_ua = self._check_suspicious_user_agent(user_agent)
        if suspicious_ua:
            analysis_result['risk_factors'].append(suspicious_ua)
            analysis_result['anomaly_score'] += 0.2
        
        # Check for rate limiting violations
        if event.get('event_type') == 'rate_limit_exceeded':
            analysis_result['risk_factors'].append('rate_limiting_violation')
            analysis_result['anomaly_score'] += 0.4
        
        # Check for authentication failures
        if event.get('event_type') in ['failed_login', 'invalid_token', 'unauthorized_access']:
            analysis_result['anomaly_score'] += 0.3
        
        # Check for critical severity
        if event.get('severity') == 'critical':
            analysis_result['anomaly_score'] += 0.2
        
        # Determine if this is an anomaly
        if analysis_result['anomaly_score'] >= 0.5:
            analysis_result['is_anomaly'] = True
        
        # Cap the score at 1.0
        analysis_result['anomaly_score'] = min(1.0, analysis_result['anomaly_score'])
        
        return analysis_result
    
    def _check_suspicious_user_agent(self, user_agent: str) -> Optional[str]:
        """Check if user agent is suspicious"""
        if not user_agent:
            return None
        
        ua_lower = user_agent.lower()
        
        # Known scanners
        scanners = ['nikto', 'sqlmap', 'nmap', 'masscan', 'burp', 'zap', 'acunetix']
        for scanner in scanners:
            if scanner in ua_lower:
                return f'security_scanner:{scanner}'
        
        # Suspicious bots
        if 'bot' in ua_lower and not any(good in ua_lower for good in ['googlebot', 'bingbot']):
            return 'suspicious_bot'
        
        # Empty or very short user agents
        if len(user_agent) < 10:
            return 'suspicious_ua_length'
        
        return None