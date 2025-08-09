PORTS = [161]
def run(host, results, **kwargs):

    import socket
    snmp_port = 161
    banner = None
    parsed = None
    try:
        snmp_get_sysdescr = bytes.fromhex(
            "30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 04 70 65 6e 67 02 01 00 02 01 00 30 0b 30 09 06 05 2b 06 01 02 01 05 00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(snmp_get_sysdescr, (host, snmp_port))
        data, _ = sock.recvfrom(512)
        banner = data.hex()
        idx = data.find(b'\x04')
        if idx != -1 and idx+1 < len(data):
            strlen = data[idx+1]
            if idx+2+strlen <= len(data):
                parsed = data[idx+2:idx+2+strlen].decode(errors='replace')
    except Exception as e:
        banner = f"SNMP banner grab failed: {e}"
    finally:
        try:
            sock.close()
        except:
            pass

    if host not in results:
        results[host] = {}
    if parsed:
        results[host].setdefault("PLUGIN-SNMP", []).append(f"SNMP sysDescr.0: {parsed}")
    elif banner:
        results[host].setdefault("PLUGIN-SNMP", []).append(f"SNMP banner (raw hex): {banner}")
    else:
        results[host].setdefault("PLUGIN-SNMP", []).append("No SNMP response on UDP/161")
