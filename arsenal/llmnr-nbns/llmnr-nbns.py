PORTS = [137, 5355]
def run(host, results, **kwargs):
    """
    Bōryoku Framework
    Author: Dion Mulaj
    LLMNR/NBNS Poisoning Detector Plugin
    - Sends LLMNR and NBNS queries to the host.
    - If the host responds, it may be vulnerable to spoofing/poisoning attacks.
    """
    import socket
    import struct
    import random
    import time

    llmnr_port = 5355
    nbns_port = 137
    hostname = "WPAD"  
    llmnr_detected = False
    nbns_detected = False
    llmnr_info = ""
    nbns_info = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        tid = random.randint(0, 0xFFFF)
        name_bytes = hostname.encode()
        llmnr_query = struct.pack(
            '>HHHHHHB', tid, 0, 1, 0, 0, 0, len(name_bytes)
        ) + name_bytes + b'\x00' + struct.pack('>HH', 1, 1)
        sock.sendto(llmnr_query, (host, llmnr_port))
        data, addr = sock.recvfrom(1024)
        if data and addr[0] == host:
            llmnr_detected = True
            llmnr_info = f"LLMNR response received from {host} (may be vulnerable to poisoning)"
    except Exception as e:
        llmnr_info = f"No LLMNR response: {e}"
    finally:
        try:
            sock.close()
        except:
            pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        tid = random.randint(0, 0xFFFF)
        def encode_nbns_name(name):
            name = name.upper().ljust(15)  
            name = name + '\x00'  
            encoded = b''
            for c in name:
                n = ord(c)
                encoded += bytes([(n >> 4) + ord('A'), (n & 0x0F) + ord('A')])
            return encoded
        nbns_name = encode_nbns_name(hostname)
        nbns_header = struct.pack('>HHHHHH', tid, 0x0010, 1, 0, 0, 0)
        question = bytes([32]) + nbns_name + struct.pack('>HH', 0x0020, 1)
        nbns_query = nbns_header + question
        sock.sendto(nbns_query, (host, nbns_port))
        data, addr = sock.recvfrom(1024)
        if data and addr[0] == host:
            nbns_detected = True
            nbns_info = f"NBNS response received from {host} (may be vulnerable to poisoning)"
    except Exception as e:
        nbns_info = f"No NBNS response: {e}"
    finally:
        try:
            sock.close()
        except:
            pass

    if host not in results:
        results[host] = {}
    msg = []
    if llmnr_detected:
        msg.append(llmnr_info)
    else:
        msg.append(llmnr_info)
    if nbns_detected:
        msg.append(nbns_info)
    else:
        msg.append(nbns_info)
    results[host].setdefault("PLUGIN-LLMNR-NBNS", []).extend(msg)
