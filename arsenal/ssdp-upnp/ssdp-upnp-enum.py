PORTS = [1900]
def run(host, results, **kwargs):
    """
    SSDP/UPnP Device Enumeration Plugin
    - Sends an SSDP M-SEARCH request to UDP port 1900 to discover UPnP devices/services
    - Reports any SSDP/UPnP responses from the target host
    """
    import socket
    import time
    info_lines = []
    ssdp_group = '239.255.255.250'
    ssdp_port = 1900
    timeout = 2
    msearch = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {ssdp_group}:{ssdp_port}\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    ).encode()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msearch, (ssdp_group, ssdp_port))
        start = time.time()
        found = False
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                if addr[0] == host:
                    info_lines.append(f"SSDP/UPnP: Response from {host} (UPnP/IoT device detected)")
                    found = True
                    break
            except socket.timeout:
                break
        if not found:
            info_lines.append(f"SSDP/UPnP: No response from {host}")
        sock.close()
    except Exception as e:
        info_lines.append(f"SSDP/UPnP: Error querying {host}: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-SSDP-UPNP-ENUM", []).extend(info_lines)
