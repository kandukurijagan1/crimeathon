#!/usr/bin/env python3
"""Local test harness for CRIMEATHON mock API. Start server separately."""
import json, urllib.request, urllib.error, sys

BASE = 'http://127.0.0.1:8765'
TOKEN = 'demo-rollcall-token'

def call(path, method='GET', source='10.10.4.12', body=None, token=TOKEN, role=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {
        'Authorization': 'Bearer ' + token,
        'X-Simulated-Source-IP': source,
        'Content-Type': 'application/json'
    }
    if role:
        headers['X-Simulated-Role'] = role
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def main():
    cases = [
        ('attendance allowed (whitelisted IP & token)', lambda: call('/v1/attendance'), 200),
        ('learner search denied to attendance role', lambda: call('/v1/learners/search'), 403),
        ('bulk export denied (role least-privilege boundary)', lambda: call('/v1/learners/export', 'POST', body={'record_count': 2300}), 403),
        ('unapproved source IP denied', lambda: call('/v1/attendance', source='203.0.113.77'), 403),
        ('invalid token denied', lambda: call('/v1/attendance', token='wrong-key'), 403),
        ('ISOLATED EXPORT LIMIT: bulk export > 100 records blocked by record ceiling', lambda: call('/v1/learners/export', 'POST', body={'record_count': 2300}, role='learner.export'), 400),
        ('ISOLATED EXPORT LIMIT: small export <= 100 records permitted for authorized role', lambda: call('/v1/learners/export', 'POST', body={'record_count': 50}, role='learner.export'), 200),
    ]
    ok = True
    for name, fn, want in cases:
        try:
            got, body = fn()
            passed = got == want
        except Exception as e:
            got = 'ERROR'
            body = {'error': str(e)}
            passed = False
        print(('PASS' if passed else 'FAIL'), name, 'expected', want, 'got', got, body)
        ok &= passed
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
