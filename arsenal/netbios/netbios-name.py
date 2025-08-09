PORTS = [137]
def run(host, results, **kwargs):
    """NetBIOS Name Service plugin: queries UDP/137 for NetBIOS names."""
    import socket
    import struct
    netbios_port = 137
    names = []
    try:
        packet = b'\x13\x37'  
        packet += b'\x00\x10'  
        packet += b'\x00\x01'  
        packet += b'\x00\x00'  
        packet += b'\x00\x00'  
        packet += b'\x00\x00'  
        packet += b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  
        packet += b'\x00'  
        packet += b'\x00\x20'  
        packet += b'\x00\x01'  

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(packet, (host, netbios_port))
        data, _ = sock.recvfrom(512)

        if len(data) > 57:
            num_names = data[56]
            offset = 57
            for _ in range(num_names):
                if offset + 18 <= len(data):
                    raw_name = data[offset:offset+15]
                    try:
                        decoded = raw_name.decode('ascii', errors='replace').rstrip(' \x00')
                    except Exception:
                        decoded = raw_name.hex()
                    names.append(decoded)
                    offset += 18  
    except Exception as e:
        names = [f"NetBIOS query failed: {e}"]
    finally:
        try:
            sock.close()
        except:
            pass

    if host not in results:
        results[host] = {}
    if names:
        for n in names:
            results[host].setdefault("PLUGIN-NETBIOS-NAME", []).append(f"NetBIOS Name: {n}")
    else:
        results[host].setdefault("PLUGIN-NETBIOS-NAME", []).append("No NetBIOS name response on UDP/137")
