"""
Detects Modbus TCP on hosts and attempts basic enumeration.
"""
import socket
PORTS = [502]

def run(host, results, **kwargs):
    lines = []
    try:
        with socket.create_connection((host, 502), timeout=4) as s:
            request = b'\x00\x01\x00\x00\x00\x06\x01\x11\x00\x00\x00\x00'
            s.sendall(request)
            resp = s.recv(64)
            if resp:
                lines.append("Modbus TCP detected on port 502.")
                if len(resp) > 8:
                    slave_id = resp[8]
                    lines.append(f"Modbus Slave ID: {slave_id}")
                else:
                    lines.append("Received response, but could not parse Slave ID.")
            else:
                lines.append("No response from Modbus service.")
    except Exception as e:
        lines.append(f"Modbus TCP detection failed: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-MODBUS", []).extend(lines)
