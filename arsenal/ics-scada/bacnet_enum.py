"""
Bōryoku Framework
Detects BACnet on hosts and attempts basic enumeration.
"""
import socket
PORTS = [47808]

def run(host, results, **kwargs):
    lines = []
    try:
        with socket.create_connection((host, 47808), timeout=4) as s:
            
            request = b'\x81\x0b\x00\x0c\x01\x20\xff\xff\xff\xff\xff\xff\x10\x08\x00\x00'
            s.sendall(request)
            resp = s.recv(64)
            if resp:
                lines.append("BACnet/IP detected on port 47808.")
                lines.append(f"Received {len(resp)} bytes from BACnet service.")
            else:
                lines.append("No response from BACnet service.")
    except Exception as e:
        lines.append(f"BACnet/IP detection failed: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-BACNET", []).extend(lines)
