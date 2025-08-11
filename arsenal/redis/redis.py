PORTS = [6379]
def run(host, results, **kwargs):
    """
    Bōryoku Framework
    Author: Dion Mulaj
    Redis Unauthenticated Access Plugin
    - Attempts to connect to Redis on port 6379 without authentication
    - Sends INFO command to retrieve server details if possible
    - Reports if the server is open and leaks information
    """
    import socket
    info_lines = []
    redis_port = 6379
    timeout = 2
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, redis_port))
        info_lines.append(f"Redis open (TCP/6379) on {host}")
        sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n" in chunk:
                    break
        except Exception:
            pass
        if data:
            lines = data.decode(errors="ignore").splitlines()
            version = next((l for l in lines if l.lower().startswith("redis_version")), None)
            mode = next((l for l in lines if l.lower().startswith("redis_mode")), None)
            protected = next((l for l in lines if l.lower().startswith("protected-mode")), None)
            info_lines.append(f"  Version: {version if version else 'Unknown'}")
            info_lines.append(f"  Mode: {mode if mode else 'Unknown'}")
            info_lines.append(f"  {protected if protected else 'Protected-mode: Unknown'}")
            if "# Server" in data.decode(errors="ignore"):
                info_lines.append("  [!] INFO output received: unauthenticated access!")
        else:
            info_lines.append("  No INFO output received (may require auth or be firewalled)")
        sock.close()
    except Exception as e:
        info_lines.append(f"No Redis (TCP/6379) on {host}: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-REDIS", []).extend(info_lines)
