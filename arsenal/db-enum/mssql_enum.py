"""
Enumerates MSSQL servers for version info via banner grab.
"""
PORTS = [1433]

import socket

def run(host, results, **kwargs):
    output = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, 1433))
        banner = s.recv(1024).decode(errors='ignore')
        output.append(f"[MSSQL] Banner: {banner.strip()}")
        s.close()
    except Exception as e:
        output.append(f"[MSSQL] Could not connect: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-DB-MSSQL", []).extend(output)
