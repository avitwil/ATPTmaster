#!/usr/bin/env python3
"""Convert `nmap -oX -` XML on stdin to JSONL (one open port per line)."""
import sys, json
import xml.etree.ElementTree as ET

data = sys.stdin.read()
if not data.strip():
    sys.exit(0)
try:
    root = ET.fromstring(data)
except ET.ParseError as e:
    print(f"nmap2json: parse error: {e}", file=sys.stderr)
    sys.exit(0)

for host in root.findall('host'):
    addr_el = host.find("address[@addrtype='ipv4']")
    if addr_el is None:
        addr_el = host.find('address')
    ip = addr_el.get('addr') if addr_el is not None else None
    hn_el = host.find('hostnames/hostname')
    hostname = hn_el.get('name') if hn_el is not None else None
    for port in host.findall('ports/port'):
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            continue
        svc = port.find('service')
        rec = {
            "ip": ip,
            "host": hostname or ip,
            "port": int(port.get('portid')),
            "protocol": port.get('protocol'),
            "service": svc.get('name') if svc is not None else None,
            "product": svc.get('product') if svc is not None else None,
            "version": svc.get('version') if svc is not None else None,
            "extrainfo": svc.get('extrainfo') if svc is not None else None,
        }
        print(json.dumps(rec))
