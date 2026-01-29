"""
SIEM Lite - Log Ingestion API
Vercel Serverless Function for receiving and analyzing logs
"""

from http.server import BaseHTTPRequestHandler
import json
import os
from datetime import datetime
import sys

sys.path.insert(0, os.path.dirname(__file__))
from log_analyzer import LogAnalyzer

from supabase import create_client, Client


class handler(BaseHTTPRequestHandler):
    
    def _set_headers(self, status_code=200, content_type='application/json'):
        """Set response headers"""
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def _get_supabase_client(self) -> Client:
        """Initialize Supabase client"""
        url = os.environ.get('SUPABASE_URL')
        # Prefer Service Role Key for backend operations to bypass RLS
        key = os.environ.get('SUPABASE_SERVICE_ROLE_KEY') or os.environ.get('SUPABASE_ANON_KEY')
        
        if not url or not key:
            raise ValueError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables")
        
        return create_client(url, key)
    
    def _read_body(self):
        """Read and parse request body"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        return json.loads(body.decode('utf-8'))
    
    def do_OPTIONS(self):
        """Handle OPTIONS request for CORS"""
        self._set_headers(204)
    
    def do_POST(self):
        """Handle POST requests for log ingestion"""
        try:
            data = self._read_body()
            
            required_fields = ['source', 'severity', 'event_type', 'message']
            for field in required_fields:
                if field not in data:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({
                        'error': f'Missing required field: {field}'
                    }).encode())
                    return
            
            valid_severities = ['critical', 'high', 'medium', 'low', 'info']
            if data['severity'] not in valid_severities:
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    'error': f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
                }).encode())
                return
            
            analyzer = LogAnalyzer()
            analysis = analyzer.analyze_event(data)
            
            event = {
                'timestamp': data.get('timestamp', datetime.utcnow().isoformat()),
                'source': data['source'],
                'severity': data['severity'],
                'event_type': data['event_type'],
                'message': data['message'],
                'source_ip': data.get('source_ip'),
                'destination_ip': data.get('destination_ip'),
                'user_agent': data.get('user_agent'),
                'username': data.get('username'),
                'metadata': {
                    **(data.get('metadata') or {}),
                    'detected_attacks': analysis['detected_attacks'],
                    'risk_factors': analysis['risk_factors'],
                },
                'is_anomaly': analysis['is_anomaly'],
                'anomaly_score': analysis['anomaly_score'],
            }
            
            supabase = self._get_supabase_client()
            result = supabase.table('log_events').insert(event).execute()
            
            # Explicitly check for database errors from Supabase
            if hasattr(result, 'error') and result.error:
                self._set_headers(500)
                self.wfile.write(json.dumps({
                    'error': 'Database operation failed',
                    'details': str(result.error)
                }).encode())
                return

            self._set_headers(201)
            response = {
                'success': True,
                'message': 'Event logged successfully',
                'event_id': result.data[0]['id'] if result.data and len(result.data) > 0 else None,
                'analysis': {
                    'is_anomaly': analysis['is_anomaly'],
                    'anomaly_score': analysis['anomaly_score'],
                    'detected_attacks': analysis['detected_attacks'],
                }
            }
            self.wfile.write(json.dumps(response).encode())
            
        except json.JSONDecodeError:
            self._set_headers(400)
            self.wfile.write(json.dumps({
                'error': 'Invalid JSON in request body'
            }).encode())
        except ValueError as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({
                'error': str(e)
            }).encode())
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            }).encode())
    
    def do_GET(self):
        """Handle GET requests - return API info"""
        self._set_headers(200)
        response = {
            'name': 'SIEM Lite Log Ingestion API',
            'version': '1.0.0',
            'endpoints': {
                'POST /api/ingest': 'Ingest a new log event',
                'GET /api/ingest': 'API information'
            }
        }
        self.wfile.write(json.dumps(response, indent=2).encode())