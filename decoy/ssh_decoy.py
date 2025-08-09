import socket
import threading
import queue

def run_decoy_server(log_queue, host='0.0.0.0', port=22):
    import random
    banners = [
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
        "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
        "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
        "SSH-2.0-OpenSSH_5.3",
        "SSH-2.0-OpenSSH_8.4p1",
        "SSH-2.0-OpenSSH_9.0p1",
        "SSH-2.0-OpenSSH_7.2p2",
        "SSH-2.0-OpenSSH_8.0",
        "SSH-2.0-OpenSSH_6.0p1",
        "SSH-2.0-OpenSSH_7.6p1",
        "SSH-2.0-OpenSSH_8.1p1",
        "SSH-2.0-OpenSSH_7.3p1",
        "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8",
        "SSH-2.0-OpenSSH_6.6.1p1 RedHat-2",
        "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        "SSH-2.0-OpenSSH_8.3p1",
        "SSH-2.0-OpenSSH_7.5p1",
        "SSH-2.0-OpenSSH_6.9p1",
        "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1",
        "SSH-2.0-OpenSSH_6.2p2 Ubuntu-6ubuntu0.5",
        "SSH-2.0-OpenSSH_7.8p1",
        "SSH-2.0-OpenSSH_8.6p1",
        "SSH-2.0-OpenSSH_8.7p1",
        "SSH-2.0-OpenSSH_9.1p1",
        "SSH-2.0-Dropbear_2019.78",
        "SSH-2.0-Dropbear_2020.80",
        "SSH-2.0-Cisco-1.25",
        "SSH-2.0-ROSSSH",
        "SSH-2.0-Paramiko_2.7.2",
        "SSH-2.0-libssh-0.7.0"
    ]
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)
    def handle_client(client_socket, addr):
        try:
            banner = random.choice(banners)
            client_socket.send((banner + "\r\n").encode())
            client_socket.recv(1024)  
            log_queue.put({'ip': addr[0], 'action': 'SSH connection'})
        except Exception:
            pass
        finally:
            client_socket.close()
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()
