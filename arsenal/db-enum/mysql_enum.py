"""
Enumerates MySQL servers for version, users, and databases.
"""
PORTS = [3306]

import socket

def run(host, results, **kwargs):
    output = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, 3306))
        banner = s.recv(1024).decode(errors='ignore')
        output.append(f"[MySQL] Banner: {banner.strip()}")
        # Simple version extraction
        if 'Ver' in banner:
            output.append(f"[MySQL] Version Info: {banner.split('Ver')[1].split()[0]}")
        s.close()
    except Exception as e:
        output.append(f"[MySQL] Could not connect: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-DB-MYSQL", []).extend(output)
