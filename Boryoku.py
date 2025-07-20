import sys
import socket
import argparse
from ipaddress import ip_network
from impacket.smbconnection import SMBConnection
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

init(autoreset=True)

AUTHOR_INFO = f"""
{Fore.CYAN}Bōryoku - SMB Guest Access Scanner
Author: Dion Mulaj
GitHub: https://github.com/dionmulaj{Style.RESET_ALL}
"""

output_lock = threading.Lock()
results = {}

def is_smb_port_open(ip, port=445):
    try:
        with socket.create_connection((ip, port), timeout=3):
            return True
    except Exception:
        return False

def check_guest_access(host):
    lines = []
    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=5)
        smb.login('', '')
        lines.append(f"[+] Anonymous login successful on {host}")

        shares = smb.listShares()
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            try:
                entries = smb.listPath(share_name, '*')
                lines.append(f"    [+] Guest access allowed on share: {share_name}")
                for entry in entries:
                    name = entry.get_longname()
                    if name not in ('.', '..'):
                        lines.append(f"        - {name}")
            except Exception:
                lines.append(f"    [-] Access denied on share: {share_name}")
        smb.close()
    except Exception:
        lines.append(f"[-] Anonymous login failed on {host}")

    with output_lock:
        results[host] = lines

def main():
    if len(sys.argv) == 1:
        print(f"{Fore.RED}No arguments supplied. Use -h or --help for usage.")
        sys.exit(1)

    print(AUTHOR_INFO)

    parser = argparse.ArgumentParser(
        epilog='Example: python3 Boryoku.py --range 192.168.1.0/24 -o output.txt'
    )
    parser.add_argument('--range', required=True, help='IP range in CIDR (e.g. 192.168.1.0/24)')
    parser.add_argument('-o', '--output', help='Save output to the specified text file')
    args = parser.parse_args()

    try:
        ip_list = [str(ip) for ip in ip_network(args.range).hosts()]
    except ValueError:
        print(f"{Fore.RED}[-] Invalid CIDR range")
        return

    print(f"{Fore.YELLOW}[~] Scanning for hosts with open SMB port...")

    open_hosts = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(is_smb_port_open, ip): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                print(f"{Fore.GREEN}[+] Host {ip} has an open SMB port")
                open_hosts.append(ip)

    if not open_hosts:
        print(f"{Fore.RED}[-] No hosts with open SMB port found.")
        return

    print(f"{Fore.YELLOW}[~] Checking guest SMB access on found hosts...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_guest_access, host) for host in open_hosts]
        for _ in as_completed(futures):
            pass  

    # Results in sorted order
    for host in sorted(results.keys()):
        for line in results[host]:
            print(line)

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(AUTHOR_INFO + '\n')
            for host in sorted(results.keys()):
                for line in results[host]:
                    f.write(line + '\n')
        print(f"{Fore.YELLOW}[~] Results saved to {args.output}")

if __name__ == '__main__':
    main()
