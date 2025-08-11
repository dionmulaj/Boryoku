"""
Bōryoku Framework
Enumerates Oracle DB servers for version info via banner grab.
"""
PORTS = [1521]

import socket

def run(host, results, **kwargs):
    output = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, 1521))
        banner = s.recv(1024).decode(errors='ignore')
        output.append(f"[OracleDB] Banner: {banner.strip()}")
        s.close()
    except Exception as e:
        output.append(f"[OracleDB] Could not connect: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-DB-ORACLE", []).extend(output)
