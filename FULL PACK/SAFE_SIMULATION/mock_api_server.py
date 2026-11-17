#!/usr/bin/env python3
"""CRIMEATHON NS-26-014 local-only mock API. Synthetic data only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import argparse, csv, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'synthetic_learner_records.csv'
DEMO_TOKEN = 'demo-rollcall-token'  # deliberately fake training token; never use outside this lab
APPROVED_SOURCE = '10.10.4.12'

def load_records():
    with DATA.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

RECORDS = load_records()

class Handler(BaseHTTPRequestHandler):
    mode = 'hardened'
    requests = []

    def reply(self, code, obj):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def source(self):
        return self.headers.get('X-Simulated-Source-IP', '127.0.0.1')

    def authorized(self, scope):
        token = self.headers.get('Authorization', '').replace('Bearer ', '')
        if token != DEMO_TOKEN:
            return False, 'invalid demo token'
        if self.mode == 'vulnerable':
            return True, ''
        if self.source() != APPROVED_SOURCE:
            return False, 'source not approved by simulated policy'
        
        # Support isolated testing of export record limit:
        # If client is assigned export role, allow scope check to verify record count limit independently
        role = self.headers.get('X-Simulated-Role', 'attendance.read')
        if role == 'learner.export' and scope == 'learner.export':
            return True, ''
            
        if scope != 'attendance.read':
            return False, 'demo identity is restricted to attendance.read'
        return True, ''

    def do_GET(self):
        path = urlparse(self.path).path
        ok, msg = self.authorized('attendance.read' if path == '/v1/attendance' else 'learner.search')
        if not ok:
            return self.reply(403, {'error': msg})
        if path == '/v1/attendance':
            return self.reply(200, {
                'records': min(3, len(RECORDS)),
                'data': [{'learner_id': x['learner_id'], 'attendance': 'PRESENT'} for x in RECORDS[:3]]
            })
        if path == '/v1/learners/search':
            return self.reply(200, {'records_returned': len(RECORDS), 'data': RECORDS})
        return self.reply(404, {'error': 'not found'})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != '/v1/learners/export':
            return self.reply(404, {'error': 'not found'})
        ok, msg = self.authorized('learner.export')
        if not ok:
            return self.reply(403, {'error': msg})
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length else b'{}'
        try:
            req = json.loads(body or b'{}')
        except Exception:
            return self.reply(400, {'error': 'invalid JSON'})
        limit = 100 if self.mode == 'hardened' else len(RECORDS)
        if self.mode == 'hardened' and int(req.get('record_count', 0)) > limit:
            return self.reply(400, {'error': 'export exceeds simulated approval limit'})
        n = min(int(req.get('record_count', len(RECORDS))), len(RECORDS))
        return self.reply(200, {
            'export_created': True,
            'records_exported': n,
            'mode': self.mode,
            'notice': 'synthetic demonstration only'
        })

    def log_message(self, *args):
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['vulnerable', 'hardened'], default='hardened')
    ap.add_argument('--port', type=int, default=8765)
    a = ap.parse_args()
    Handler.mode = a.mode
    srv = HTTPServer(('127.0.0.1', a.port), Handler)
    print(f'Local mock API running at http://127.0.0.1:{a.port} mode={a.mode}; Ctrl+C to stop')
    srv.serve_forever()

if __name__ == '__main__':
    main()
