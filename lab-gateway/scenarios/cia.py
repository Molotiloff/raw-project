#!/usr/bin/env python3
"""Bounded CIA checks against a locally forwarded, synthetic-data lab gateway."""
import argparse
import asyncio
import ipaddress
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

OPENER = urllib.request.build_opener(NoRedirect)

def local_url(url):
    p = urllib.parse.urlsplit(url)
    try:
        local = p.hostname == 'localhost' or ipaddress.ip_address(p.hostname or '').is_loopback
    except ValueError:
        local = False
    if p.scheme != 'http' or not local or p.username or p.password or p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('Use a loopback HTTP origin such as http://127.0.0.1:8000 (via port-forward)')
    return url.rstrip('/')

def request(base, method, path, token=None, payload=None, raw=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        with OPENER.open(req, timeout=5) as resp:
            return resp.status, resp.read(65536), round((time.monotonic()-start)*1000, 2)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536), round((time.monotonic()-start)*1000, 2)

def check(results, category, name, passed, detail):
    results.append({'category': category, 'scenario': name, 'result': 'PASS' if passed else 'FAIL', 'detail': detail})

def percentile(values, fraction):
    values = sorted(values)
    return values[max(0, min(len(values)-1, int((len(values)-1)*fraction + 0.999999)))]

def run_http(args, results):
    base, reader, producer = args.url, args.reader, args.producer
    obj = urllib.parse.quote(args.object, safe='')
    other = urllib.parse.quote(args.other_object, safe='')
    query = '/query?object_id=' + obj
    status, _, _ = request(base, 'GET', '/health/ready')
    if status != 200:
        raise RuntimeError(f'Preflight readiness failed: HTTP {status}')
    status, _, _ = request(base, 'GET', query, reader)
    if status != 200:
        raise RuntimeError(f'Preflight reader access failed: HTTP {status}; check credentials and object ACL')
    status, _, _ = request(base, 'GET', query)
    check(results, 'C', 'T1: HTTP без токена', status == 401, {'http_status': status})
    status, _, _ = request(base, 'GET', '/query?object_id=' + other, reader)
    check(results, 'C', 'T2: чужая история', status == 403, {'http_status': status})
    status, body, _ = request(base, 'POST', '/events', reader, {'object_id': args.object, 'payload': {'test': 'unauthorized-write'}})
    check(results, 'I', 'запись без роли producer', status == 403, {'http_status': status})
    status, body, _ = request(base, 'POST', '/events', producer, raw=b'{invalid json')
    check(results, 'I', 'T10: некорректный JSON', status == 422, {'http_status': status})
    marker = uuid.uuid4().hex
    payload = {'test_run': marker, 'text': 'synthetic-данные', 'value': 42}
    status, body, _ = request(base, 'POST', '/events', producer, {'object_id': args.object, 'payload': payload})
    if status != 201:
        raise RuntimeError(f'Producer preflight failed: HTTP {status}; check token, role and rate limit')
    created = json.loads(body)
    status, body, _ = request(base, 'GET', query + '&after=' + str(created['id']-1) + '&limit=10', reader)
    data = json.loads(body) if status == 200 else {}
    found = [x for x in data.get('events', []) if x['id'] == created['id']]
    check(results, 'I', 'запись и чтение без изменения', len(found) == 1 and found[0]['payload'] == payload, {'http_status': status, 'event_id': created['id']})
    status, _, _ = request(base, 'POST', '/events', producer, {'object_id': args.object, 'payload': {'data': 'x' * 5000}})
    check(results, 'A', 'T7: большой payload отклонён', status == 413, {'http_status': status, 'payload_bytes': 5000})
    latencies = []
    statuses = []
    for _ in range(args.samples):
        status, _, ms = request(base, 'GET', query, reader)
        statuses.append(status)
        latencies.append(ms)
    check(results, 'A', 'контрольные запросы после ошибок', all(x == 200 for x in statuses), {'samples': len(statuses), 'http_statuses': statuses, 'p50_ms': round(statistics.median(latencies), 2), 'p95_ms': percentile(latencies, .95)})

async def run_ws(args, results):
    try:
        from websockets.asyncio.client import connect
        from websockets.exceptions import InvalidStatus, ConnectionClosed
    except ImportError:
        results.append({'category': 'C/A', 'scenario': 'WebSocket scenarios', 'result': 'SKIP', 'detail': 'Install scenarios/requirements.txt'})
        return
    base = args.url.replace('http://', 'ws://', 1) + '/subscription?object_id='
    async def denied(name, object_id, token):
        try:
            async with connect(base + urllib.parse.quote(object_id, safe=''), additional_headers={'Authorization': 'Bearer '+token} if token else None, open_timeout=5):
                check(results, 'C', name, False, {'handshake': 'accepted'})
        except InvalidStatus as exc:
            status = exc.response.status_code
            check(results, 'C', name, status == 403, {'http_status': status})
        except (OSError, TimeoutError, ConnectionClosed) as exc:
            check(results, 'C', name, False, {'error': type(exc).__name__, 'note': 'transport failure is not evidence of access control'})
    await denied('T1: WS без токена', args.object, None)
    await denied('T2: WS чужой объект', args.other_object, args.reader)
    try:
        async with connect(base + urllib.parse.quote(args.object, safe=''), additional_headers={'Authorization': 'Bearer '+args.reader}, open_timeout=5) as ws:
            marker = uuid.uuid4().hex
            payload = {'test_run': marker, 'text': 'synthetic-websocket'}
            status, body, _ = await asyncio.to_thread(request, args.url, 'POST', '/events', args.producer, {'object_id': args.object, 'payload': payload})
            if status != 201:
                raise RuntimeError(f'publish HTTP {status}')
            event_id = json.loads(body)['id']
            received = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            check(results, 'I', 'доставка события по WS', received.get('type') == 'event' and received.get('data', {}).get('id') == event_id and received.get('data', {}).get('payload') == payload, {'event_id': event_id})
            await ws.send('complete')
    except Exception as exc:
        check(results, 'I', 'доставка события по WS', False, {'error': type(exc).__name__, 'note': 'check lab logs and producer rights'})
    # Allow the server to release the preceding connection before the limit test.
    await asyncio.sleep(0.5)
    sockets = []
    try:
        for _ in range(args.connection_limit):
            sockets.append(await connect(base + urllib.parse.quote(args.object, safe=''), additional_headers={'Authorization': 'Bearer '+args.reader}, open_timeout=5))
        try:
            extra = await connect(base + urllib.parse.quote(args.object, safe=''), additional_headers={'Authorization': 'Bearer '+args.reader}, open_timeout=5)
        except InvalidStatus as exc:
            status = exc.response.status_code
            check(results, 'A', 'T4/T5: лимит подключений', status == 403, {'http_status': status, 'held_connections': len(sockets), 'note': '403 подтверждает отклонение handshake; проверьте событие connection_limited в журнале'})
        else:
            await extra.close()
            check(results, 'A', 'T4/T5: лимит подключений', False, {'handshake': 'accepted', 'held_connections': len(sockets)})
    except Exception as exc:
        check(results, 'A', 'T4/T5: лимит подключений', False, {'error': type(exc).__name__, 'note': 'could not establish expected initial connections'})
    finally:
        for ws in sockets:
            await ws.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    parser.add_argument('--object', default='demo')
    parser.add_argument('--other-object', default='other')
    parser.add_argument('--samples', type=int, default=5, choices=range(1, 21))
    parser.add_argument('--connection-limit', type=int, default=4, choices=range(1, 11))
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        args.url = local_url(args.url)
        if args.object == args.other_object:
            raise ValueError('object and other-object must differ')
        args.reader = os.environ['LAB_READER_TOKEN']
        args.producer = os.environ['LAB_PRODUCER_TOKEN']
        if not args.reader or not args.producer or args.reader == args.producer:
            raise ValueError('reader and producer must be distinct nonempty tokens')
    except (KeyError, ValueError) as exc:
        parser.error(str(exc))
    results = []
    error = None
    try:
        run_http(args, results)
        asyncio.run(run_ws(args, results))
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'target': args.url, 'object': args.object, 'other_object': args.other_object, 'results': results, 'error': error, 'notes': ['Only synthetic data; results do not prove regulatory compliance.', 'WebSocket connection limit is per process, not cluster-wide.']}
    with open(args.output, 'x', encoding='utf-8') as out:
        json.dump(report, out, ensure_ascii=False, indent=2)
        out.write('\n')
    for result in results:
        print(f"{result['result']:4} {result['category']:3} {result['scenario']}: {result['detail']}")
    if error:
        print('ERROR:', error, file=sys.stderr)
    print('Report:', args.output)
    return 2 if error or any(r['result'] == 'SKIP' for r in results) else (1 if any(r['result'] == 'FAIL' for r in results) else 0)

if __name__ == '__main__':
    sys.exit(main())
