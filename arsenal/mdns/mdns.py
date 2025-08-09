PORTS = [5353]
def run(host, results, **kwargs):
    """
    mDNS/Bonjour Service Discovery Plugin
    - Sends a multicast DNS query to port 5353 to discover advertised services on the LAN
    - Reports any mDNS responses from the target host
    """
    import socket
    import struct
    import time
    info_lines = []
    mdns_group = '224.0.0.251'
    mdns_port = 5353
    timeout = 2
    query = b'\x00\x00'  
    query += b'\x00\x00'  
    query += b'\x00\x01' 
    query += b'\x00\x00'  
    query += b'\x00\x00'  
    query += b'\x00\x00'  
    query += b'\x09_services\x07_dns-sd\x04_udp\x05local\x00'
    query += b'\x00\x0c' 
    query += b'\x00\x01' 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(query, (mdns_group, mdns_port))
        start = time.time()
        found = False
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                if addr[0] == host:
                    info_lines.append(f"mDNS: Response from {host} (Bonjour/Apple/IoT service detected)")
                    found = True
                    break
            except socket.timeout:
                break
        if not found:
            info_lines.append(f"mDNS: No response from {host}")
        sock.close()
    except Exception as e:
        info_lines.append(f"mDNS: Error querying {host}: {e}")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-MDNS", []).extend(info_lines)
