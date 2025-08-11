PORTS = [389]
def run(host, results, **kwargs):
    """
    Bōryoku Framework
    Author: Dion Mulaj
    LDAP/Active Directory Anonymous Enumerator Plugin
    - Attempts an anonymous LDAP bind to the target host (TCP/389)
    - Retrieves root DSE and basic directory info if allowed
    """
    import socket
    import struct
    import sys

    ldap_port = 389
    info_lines = []
    try:
        bind_req = bytes.fromhex(
            "30 1c 02 01 03 60 17 02 01 03 04 00 80 00 a0 0f 30 0d 04 00 04 00 02 01 00 02 01 00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, ldap_port))
        sock.sendall(bind_req)
        data = sock.recv(4096)
        if b'\x61' in data:  
            info_lines.append(f"LDAP anonymous bind allowed on {host} (TCP/389)")
            search_req = bytes.fromhex(
                "30 3c 02 01 04 63 37 04 00 0a 01 00 0a 01 00 02 01 00 02 01 00 01 01 00 a0 0b a3 09 04 01 6f 04 00 87 01 2a 30 13 04 01 2a 04 00 04 01 2b 04 00 04 01 2d 04 00"
            )
            sock.sendall(search_req)
            data2 = sock.recv(4096)
            if b'rootDSE' in data2 or b'domain' in data2 or b'objectClass' in data2:
                info_lines.append(f"LDAP rootDSE info received from {host} (partial):")
              
                info_lines.append(data2[:128].hex())
            else:
                info_lines.append(f"LDAP rootDSE query sent, but no useful info returned from {host}")
        else:
            info_lines.append(f"LDAP anonymous bind denied or no response from {host}")
    except Exception as e:
        info_lines.append(f"LDAP connection failed: {e}")
    finally:
        try:
            sock.close()
        except:
            pass
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-LDAP-AD-ENUM", []).extend(info_lines)
