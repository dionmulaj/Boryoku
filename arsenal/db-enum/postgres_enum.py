"""
Bōryoku Framework
Enumerates PostgreSQL servers for version info via banner grab.
"""
PORTS = [5432]

import socket

def run(host, results, **kwargs):
    output = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, 5432))
        banner = s.recv(1024).decode(errors='ignore')
        output.append(f"[PostgreSQL] Banner: {banner.strip()}")
        s.close()
    except Exception as e:
        output.append(f"[PostgreSQL] Could not connect: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-DB-POSTGRES", []).extend(output)
