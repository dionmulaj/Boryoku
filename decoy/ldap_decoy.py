import socket
import threading
import queue

def run_decoy_server(log_queue, host='0.0.0.0', port=389):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)
    def handle_client(client_socket, addr):
        try:
            client_socket.recv(1024)  
            log_queue.put({'ip': addr[0], 'action': 'LDAP connection'})
        except Exception:
            pass
        finally:
            client_socket.close()
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()
