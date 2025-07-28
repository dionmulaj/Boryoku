import sys
import socket
import argparse
from ipaddress import ip_network
from impacket.smbconnection import SMBConnection
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from ftplib import FTP, error_perm
from tqdm import tqdm
import requests
import os
import asyncio
import httpx
import re
import json
import random
import time
import uuid
import subprocess


init(autoreset=True)

AUTHOR_INFO = f"""
{Fore.CYAN}Bōryoku V2 - An Advanced Modular Red Team Tool
Author: Dion Mulaj
GitHub: https://github.com/dionmulaj{Style.RESET_ALL}
"""

output_lock = threading.Lock()
results = {}  

def stealth_delay(min_delay=2.5, max_delay=5.0):
    """Introduce random delay for stealth mode"""
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)

async def stealth_delay_async(min_delay=2.5, max_delay=5.0):
    delay = random.uniform(min_delay, max_delay)
    await asyncio.sleep(delay)


def is_port_open(ip, port, retries=2, timeout=5):
    for _ in range(retries):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except:
            time.sleep(0.2)  
    return False


def is_suspicious_smb(share_names):
    
    return len(share_names) == 1 and share_names[0].lower() in ['ipc$', 'default']

def load_honeypot_detection_rules():
    path = os.path.join(os.path.dirname(__file__), "rules", "honeypot_detection_rules.json")
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not load honeypot_detection_rules.json: {e}{Style.RESET_ALL}")
        return {}



def load_av_signatures():
    path = os.path.join(os.path.dirname(__file__), "signatures", "av_signatures.json")
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not load av_signatures.json: {e}{Style.RESET_ALL}")
        return {}

def calculate_av_fingerprint(protocol, banner, results=None, av_rules=None):
    if av_rules is None:
        av_rules = load_av_signatures()

    findings = []
    banner_lower = banner.lower()

    
    if protocol.lower() in ["http", "https"]:
        for av_name, keywords in av_rules.get("http_banners", {}).items():
            if any(k.lower() in banner_lower for k in keywords):
                findings.append(f"Detected {av_name} in HTTP banner")

   
    if protocol.lower() == "ftp" and results:
        files_list = results if isinstance(results, list) else []
        for av_name, patterns in av_rules.get("ftp_files", {}).items():
            if any(p.lower() in f.lower() for f in files_list for p in patterns):
                findings.append(f"FTP AV/EDR/FW Artifact: {av_name}")

    
    if protocol.lower() == "smb" and results:
        files_list = results.get("files", []) if isinstance(results, dict) else []
        for av_name, patterns in av_rules.get("smb_files", {}).items():
            if any(p.lower() in f.lower() for f in files_list for p in patterns):
                findings.append(f"SMB AV/EDR/FW Artifact: {av_name}")


    score = len(findings)
    return score, findings



def load_av_ports():
    path = os.path.join(os.path.dirname(__file__), "signatures", "av_ports.json")
    try:
        with open(path, 'r') as f:
            return json.load(f).get("common_ports", {})
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not load av_ports.json: {e}{Style.RESET_ALL}")
        return {}



def detect_av_ports(host_open_ports, av_ports_db):
    detected = []
    for port in host_open_ports:
        service = av_ports_db.get(str(port))
        if service:
            detected.append(f"Port {port} => {service}")
    return detected


def load_vendor_fingerprints():
    path = os.path.join(os.path.dirname(__file__), "signatures", "oui_vendors.json")
    try:
        with open(path, 'r') as f:
            return json.load(f).get("mac_vendors", {})
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not load oui_vendors.json: {e}{Style.RESET_ALL}")
        return {}

def detect_vendor_from_mac(mac_address, vendor_db):
    for prefix, vendor in vendor_db.items():
        if mac_address.lower().startswith(prefix.lower()):
            return f"Vendor Detected via MAC prefix {prefix} ({vendor})"
    return "No vendor signature detected"



def calculate_honeypot_score(protocol, banner, results=None, rules=None):
    if not rules:
        rules = load_honeypot_detection_rules()

    score = 0
    details = []
    banner_lower = banner.lower()

    
    for keyword, value in rules.get("contains", {}).items():
        if keyword in banner_lower:
            score += value
            details.append(f"Keyword match: '{keyword}' (+{value})")

    
    if "length" in rules:
        min_len = rules["length"].get("min", 0)
        len_score = rules["length"].get("score", 0)
        if len(banner) > min_len:
            score += len_score
            details.append(f"Banner length > {min_len} (+{len_score})")

    
    if protocol.lower() in ["http", "https"] and results:
        total = len(results)
        count_200 = sum(1 for r in results if r and not isinstance(r, Exception) and r.status_code == 200)
        max_allowed = rules.get("http", {}).get("max_allowed_200s", 0.65)
        if total > 0 and (count_200 / total) > max_allowed:
            value = rules.get("http", {}).get("score", 0)
            score += value
            details.append(f"Too many HTTP Status Code 200s > {max_allowed*100}% (+{value})")

        suspicious_paths = rules.get("http", {}).get("suspicious_paths", [])
        suspicious_score = rules.get("http", {}).get("suspicious_path_score", 0)
        for path, resp in zip(suspicious_paths, results):
            if resp and not isinstance(resp, Exception) and resp.status_code == 200 and path.lower() in str(resp.url).lower():
                score += suspicious_score
                details.append(f"HTTP suspicious path '{path}' returned 200 (+{suspicious_score})")

    
    if protocol.lower() == "ftp" and results:
        fake_files = rules.get("ftp", {}).get("fake_file_patterns", {}).get("files", [])
        fake_score = rules.get("ftp", {}).get("fake_file_patterns", {}).get("score", 0)
        files_listed = results if isinstance(results, list) else []
        for fake_file in fake_files:
            if any(fake_file in f.lower() for f in files_listed):
                score += fake_score
                details.append(f"FTP fake file '{fake_file}' found (+{fake_score})")

        min_count = rules.get("ftp", {}).get("unrealistically_clean", {}).get("min_count", 0)
        clean_score = rules.get("ftp", {}).get("unrealistically_clean", {}).get("score", 0)
        if len(files_listed) <= min_count:
            score += clean_score
            details.append(f"FTP unrealistically clean (<= {min_count} files) (+{clean_score})")

    
    if protocol.lower() == "smb" and results:
        suspicious_shares = rules.get("smb", {}).get("only_suspicious_shares", {}).get("shares", [])
        suspicious_score = rules.get("smb", {}).get("only_suspicious_shares", {}).get("score", 0)
        fake_files = rules.get("smb", {}).get("fake_files", {}).get("files", [])
        fake_score = rules.get("smb", {}).get("fake_files", {}).get("score", 0)

        shares = results.get("shares", []) if results else []
        files = results.get("files", []) if results else []

        suspicious_shares_upper = [share.upper() for share in suspicious_shares]

        if shares and all(share.upper() in suspicious_shares_upper for share in shares):
            score += suspicious_score
            details.append(f"Only suspicious SMB shares found (+{suspicious_score})")

        for fake_file in fake_files:
            if any(fake_file in f.lower() for f in files):
                score += fake_score
                details.append(f"SMB fake file '{fake_file}' found (+{fake_score})")

    return score, details
    

def honeypot_verdict(score):
    if score >= 10:
        return f"{Fore.MAGENTA}[Honeypot Status]{Style.RESET_ALL} {Fore.RED}HONEYPOT DETECTED!!!!! (Score: {score}){Style.RESET_ALL}"
    elif score >= 7:
        return f"{Fore.MAGENTA}[Honeypot Status]{Style.RESET_ALL} {Fore.YELLOW}POTENTIAL HONEYPOT (Score: {score}){Style.RESET_ALL}"
    elif score >= 5:
        return f"{Fore.MAGENTA}[Honeypot Status]{Style.RESET_ALL} {Fore.BLUE}Low Possibility of Honeypot (Score: {score}){Style.RESET_ALL}"
    else:
        return f"{Fore.MAGENTA}[Honeypot Status]{Style.RESET_ALL} Normal Service (Score: {score})"



def check_smb_guest_access(host, stealth=False):
    lines = []
    shares_list = []
    files_list = []
    banner = ""  

    if stealth:
        stealth_delay()

    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=5)
        smb.login('', '')

        server_name = smb.getServerName()
        banner = server_name or ""
        lines.append(f"{Fore.CYAN}[i] SMB Server Name: {server_name}{Style.RESET_ALL}")

        lines.append(f"{Fore.GREEN}[+] SMB anonymous login successful on {host}{Style.RESET_ALL}")

        shares = smb.listShares()
        shares_list = [share['shi1_netname'].rstrip('\x00').upper() for share in shares]

        for share in shares:
            share_name = share['shi1_netname'][:-1]

            if stealth:
                stealth_delay()

            try:
                entries = smb.listPath(share_name, '*')
                files_list.extend([entry.get_longname() for entry in entries if entry.get_longname() not in ('.', '..')])
                lines.append(f"{Fore.GREEN}    [+] SMB guest access allowed on share: {share_name}{Style.RESET_ALL}")
                for entry in entries:
                    name = entry.get_longname()
                    if name not in ('.', '..'):
                        lines.append(f"{Fore.WHITE}        - {name}{Style.RESET_ALL}")
            except Exception:
                lines.append(f"{Fore.RED}    [-] Access denied on share: {share_name}{Style.RESET_ALL}")
        smb.close()
    except Exception:
        lines.append(f"{Fore.RED}[-] SMB anonymous login failed on {host}{Style.RESET_ALL}")

    
    score, details = calculate_honeypot_score("smb", banner, results={"shares": shares_list, "files": files_list})
    lines.append(honeypot_verdict(score))
    if details:
        lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
        for d in details:
            lines.append(f"  - {d}")
   
    
    av_score, av_details = calculate_av_fingerprint("smb", banner, results={"shares": shares_list, "files": files_list})
    if av_details:
        lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL}{Fore.RED} AV/EDR/FW FINGERPINT DETECTED!!!!!{Style.RESET_ALL}")
        for d in av_details:
            lines.append(f"  - {d}")
    else:
        lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL} No AV/EDR/FW Fingerprint Detected")

    with output_lock:
        if host not in results:
            results[host] = {}
        results[host].setdefault("SMB", []).extend(lines)


def check_ftp_guest_access(host, stealth=False):
    lines = []
    files_listed = []
    banner = ""

    if stealth:
        stealth_delay() 


    try:
        ftp = FTP()
        ftp.connect(host, 21, timeout=5)
        banner = ftp.getwelcome()
        lines.append(f"{Fore.CYAN}[i] FTP Banner: {banner}{Style.RESET_ALL}")

        ftp.login()
        lines.append(f"{Fore.GREEN}[+] FTP anonymous login successful on {host}{Style.RESET_ALL}")
        try:
            files = ftp.nlst()
            if files:
                files_listed = files
                lines.append(f"{Fore.GREEN}    [+] FTP file list:{Style.RESET_ALL}")
                for file in files:
                    lines.append(f"{Fore.WHITE}        - {file}{Style.RESET_ALL}")
        except error_perm:
            lines.append(f"{Fore.RED}    [-] FTP access to list files was denied.{Style.RESET_ALL}")
        ftp.quit()
    except Exception:
        lines.append(f"{Fore.RED}[-] FTP anonymous login failed on {host}{Style.RESET_ALL}")

    
    score, details = calculate_honeypot_score("ftp", banner, results=files_listed)
    lines.append(honeypot_verdict(score))
    if details:
        lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
        for d in details:
            lines.append(f"  - {d}")

    
    av_score, av_details = calculate_av_fingerprint("ftp", banner, results=files_listed)
    if av_details:
        lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL}{Fore.RED} AV/EDR/FW FINGERPINT DETECTED!!!!!{Style.RESET_ALL}")
        for d in av_details:
            lines.append(f"  - {d}")
    else:
        lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL} No AV/EDR/FW Fingerprint Detected")

    with output_lock:
        if host not in results:
            results[host] = {}
        results[host].setdefault("FTP", []).extend(lines)



wordlist_path = os.path.join("wordlists", "dirs.txt")
try:
    HTTP_WORDLIST = [line.strip() for line in open(wordlist_path) if line.strip()]
except FileNotFoundError:
    HTTP_WORDLIST = []

http_semaphore = asyncio.Semaphore(50)  

async def fetch(client, url):
    async with http_semaphore:
        try:
            resp = await client.get(url)
            return resp
        except Exception:
            return None

async def check_http_critical_files_async(host, use_https=False, stealth=False):
    lines = []
    protocol = 'https' if use_https else 'http'
    base_url = f"{protocol}://{host}"

    if stealth:
        await stealth_delay_async()

    if not HTTP_WORDLIST:
        lines.append(f"{Fore.RED}[!] Could not find wordlist at {wordlist_path}{Style.RESET_ALL}")
        with output_lock:
            if host not in results:
                results[host] = {}
            results[host].setdefault("HTTPS" if use_https else "HTTP", []).extend(lines)
        return

    async with httpx.AsyncClient(verify=False, timeout=5) as client:
        server_header = "N/A"  

        
        try:
            root_resp = await client.head(base_url)
            server_header = root_resp.headers.get('Server', 'N/A')
            lines.append(f"{Fore.CYAN}[i] HTTP Server: {server_header}{Style.RESET_ALL}")
        except Exception:
            lines.append(f"{Fore.YELLOW}[!] Could not retrieve HTTP(S) headers from {base_url}{Style.RESET_ALL}")

        tasks = []
        for path in HTTP_WORDLIST:
            if stealth:
                await stealth_delay_async(2.5, 5.0)
            url = f"{base_url}/{path}"
            tasks.append(fetch(client, url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for path, resp in zip(HTTP_WORDLIST, responses):
            if isinstance(resp, Exception) or resp is None:
                continue
            if resp.status_code == 200:
                lines.append(f"{Fore.GREEN}[+] Found {path} on {resp.url}{Style.RESET_ALL}")

        
        score, details = calculate_honeypot_score(protocol, server_header, results=responses)
        lines.append(honeypot_verdict(score))
        if details:
            lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
            for d in details:
                lines.append(f"  - {d}")

        
        av_score, av_details = calculate_av_fingerprint(protocol, server_header)
        if av_details:
            lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL}{Fore.RED} AV/EDR/FW FINGERPINT DETECTED!!!!!{Style.RESET_ALL}")
            for d in av_details:
                lines.append(f"  - {d}")
        else:
            lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL} No AV/EDR/FW Fingerprint Detected")

    with output_lock:
        if host not in results:
            results[host] = {}
        results[host].setdefault("HTTPS" if use_https else "HTTP", []).extend(lines)


def run_async_http_scans(hosts_http, hosts_https, stealth=False):
    async def runner():
        tasks = []
        for host in hosts_http:
            tasks.append(check_http_critical_files_async(host, use_https=False, stealth=stealth))
        for host in hosts_https:
            tasks.append(check_http_critical_files_async(host, use_https=True))
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Checking HTTP(S) for exposed files and directories"):
            await f

    asyncio.run(runner())


def strip_ansi(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mK]')
    return ansi_escape.sub('', text)

def send_to_discord_webhook(message, url):
    try:
        filename = "boryoku_results.txt"
        with open(filename, 'w') as f:
            f.write(message)

        with open(filename, 'rb') as file:
            response = requests.post(
                url,
                files={"file": (filename, file)},
                data={"content": "📄  Bōryoku scan results attached."},
                timeout=10
            )

        os.remove(filename)

        if response.status_code in [200, 204]:
            print(f"{Fore.GREEN}[+] Results sent to Discord webhook.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Discord webhook returned status code {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[-] Failed to send results to webhook: {e}{Style.RESET_ALL}")

def send_message_to_slack(message, bot_token, channel_id):
    try:
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {bot_token}",
                "Content-Type": "application/json"
            },
            json={
                "channel": channel_id,
                "text": message
            },
            timeout=10
        )
        resp_json = response.json()
        if resp_json.get("ok"):
            print(f"{Fore.GREEN}[+] Results sent to Slack - integrated app.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Slack API error: {resp_json.get('error')}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to send message to Slack: {e}{Style.RESET_ALL}")


def main():
    if len(sys.argv) == 1:
        print(f"{Fore.RED}No arguments supplied. Use -h or --help for usage.")
        sys.exit(1)

    print(AUTHOR_INFO)

    parser = argparse.ArgumentParser(
        epilog='Example: python3 boryoku.py -t 192.168.1.0/24 -smb -ftp -http --stealth -o results.txt'
    )
    parser.add_argument('-t', required=True, metavar='TARGET', help='Target IP / Range in CIDR (e.g. 192.168.1.25 OR 192.168.1.0/24)')
    parser.add_argument('-smb', action='store_true', help='Scan for SMB guest access')
    parser.add_argument('-ftp', action='store_true', help='Scan for FTP anonymous access')
    parser.add_argument('-http', action='store_true', help='Scan for HTTP(S) critical files')
    parser.add_argument('-all', action='store_true', help='Scan SMB, FTP, and HTTP(S)')
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode with randomized packet delays")
    parser.add_argument('--anti-virus', action='store_true', help='Detect AV/EDR/FW ports')
    parser.add_argument('-o', '--output', help='Save output to the specified text file')
    parser.add_argument('--discord', action='store_true', help='Send results to Discord webhook')
    parser.add_argument('--slack', action='store_true', help='Send results to Slack webhook')
    args = parser.parse_args()

    stealth_enabled = args.stealth
    anti_virus_enabled = args.anti_virus

    
    if anti_virus_enabled:
        av_ports = load_av_ports()
        common_ports = av_ports
    else:
        common_ports = {}

    
    if not any([args.smb, args.ftp, args.http, args.all, args.anti_virus]):
        print(f"{Fore.RED}[-] You must specify at least one scan mode: -smb, -ftp, -http, -all, or --anti-virus")
        return

    try:
        ip_list = [str(ip) for ip in ip_network(args.t, strict=False)]
    except ValueError:
        print(f"{Fore.RED}[-] Invalid CIDR range")
        return

    scan_smb = args.smb or args.all
    scan_ftp = args.ftp or args.all
    scan_http = args.http or args.all

    ports_to_check = []
    if scan_smb:
        ports_to_check.append(445)
    if scan_ftp:
        ports_to_check.append(21)
    if scan_http:
        ports_to_check.extend([80, 443])
    if anti_virus_enabled:
        ports_to_check.extend([int(p) for p in common_ports.keys() if int(p) not in ports_to_check])

    open_hosts = {port: [] for port in ports_to_check}

    print(f"{Fore.MAGENTA}[~] Scanning for open ports...{Style.RESET_ALL}")
    open_ports_messages = []

    with ThreadPoolExecutor(max_workers=200) as executor:
        future_to_ip_port = {
            executor.submit(is_port_open, ip, port): (ip, port)
            for ip in ip_list for port in ports_to_check
        }
        futures = list(future_to_ip_port.keys())

        with tqdm(total=len(futures), desc="Scanning for open ports") as pbar:
            for future in as_completed(futures):
                ip, port = future_to_ip_port[future]
                if future.result():
                    open_hosts[port].append(ip)
                pbar.update(1)

    host_ports = {}
    for port, hosts in open_hosts.items():
        for host in hosts:
            host_ports.setdefault(host, []).append(port)

    for host in sorted(host_ports.keys()):
        ports_str = ",".join(str(p) for p in sorted(host_ports[host]))
        print(f"{Fore.BLUE}[+] Host {host} has port(s) {ports_str} open{Style.RESET_ALL}")

    if anti_virus_enabled:
        for host, ports in host_ports.items():
            detected = []
            for port in set(ports):
                port_str = str(port)
                if port_str in common_ports:
                    detected.append(f"{port} ({common_ports[port_str]})")

            if detected:
                av_line = f"{Fore.RED}[AV/EDR/FW Port Detection] {host} => {', '.join(detected)}{Style.RESET_ALL}"
                if host not in results:
                    results[host] = {}
                results[host].setdefault("AV-PORT-DETECTION", []).append(av_line)

    if scan_smb and not open_hosts.get(445):
        print(f"{Fore.RED}[-] No hosts with open SMB port found.{Style.RESET_ALL}")
    if scan_ftp and not open_hosts.get(21):
        print(f"{Fore.RED}[-] No hosts with open FTP port found.{Style.RESET_ALL}")
    if scan_http and not (open_hosts.get(80) or open_hosts.get(443)):
        print(f"{Fore.RED}[-] No hosts with open HTTP/HTTPS port found.{Style.RESET_ALL}")

    print(f"{Fore.MAGENTA}[~] Performing guest/anonymous access checks...{Style.RESET_ALL}")

    smb_hosts = open_hosts.get(445, []) if scan_smb else []
    ftp_hosts = open_hosts.get(21, []) if scan_ftp else []

    max_workers_smb = min(20, len(smb_hosts)) or 1
    max_workers_ftp = min(20, len(ftp_hosts)) or 1
    max_workers = max(max_workers_smb, max_workers_ftp, 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []

        if scan_smb:
            for host in smb_hosts:
                futures.append(executor.submit(check_smb_guest_access, host, stealth=stealth_enabled))
        if scan_ftp:
            for host in ftp_hosts:
                futures.append(executor.submit(check_ftp_guest_access, host, stealth=stealth_enabled))

        for _ in tqdm(as_completed(futures), total=len(futures), desc="Checking SMB/FTP guest access"):
            pass

    if scan_http:
        hosts_http = open_hosts.get(80, [])
        hosts_https = open_hosts.get(443, [])
        run_async_http_scans(hosts_http, hosts_https, stealth_enabled)

    
    vendor_db = load_vendor_fingerprints()

    def get_mac_address(ip):
        try:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            pid = subprocess.Popen(["arp", "-n", ip], stdout=subprocess.PIPE)
            s = pid.communicate()[0].decode()
            match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", s)
            if match:
                return match.group(0)
        except Exception:
            return None

    for host in sorted(results.keys()):
        mac = get_mac_address(host)
        if mac:
            verdict = detect_vendor_from_mac(mac, vendor_db)
        else:
            verdict = "MAC address not available"
        results[host].setdefault("VENDOR-DETECTION", []).append(
            f"{Fore.MAGENTA}[Vendor Detection]{Style.RESET_ALL} {verdict}"
        )


    for host in sorted(results.keys()):
        print("\n\n") 
        print(f"{Fore.CYAN}==========Host: {host}=========={Style.RESET_ALL}")
        host_protocols = results[host]

        for protocol in ["SMB", "FTP", "HTTP", "HTTPS", "AV-PORT-DETECTION", "VENDOR-DETECTION"]:
            if protocol == "SMB":
                print(f"{Fore.YELLOW}Service: SMB{Style.RESET_ALL}")
            elif protocol == "FTP":
                print(f"{Fore.YELLOW}Service: FTP{Style.RESET_ALL}")
            elif protocol in ["HTTP", "HTTPS"]:
                if protocol == "HTTP":
                    print(f"{Fore.YELLOW}Service: HTTP/HTTPS{Style.RESET_ALL}")
            elif protocol == "AV-PORT-DETECTION":
                print(f"{Fore.YELLOW}AV/EDR/FW Port Detection:{Style.RESET_ALL}")
            elif protocol == "VENDOR-DETECTION":
                print(f"{Fore.YELLOW}Vendor Detection:{Style.RESET_ALL}")


            if protocol in host_protocols:
                for line in host_protocols[protocol]:
                    if "No results or not scanned" in line or "No AV/EDR/FW Fingerprint Detected" in line:
                        print(f"    {Fore.LIGHTBLACK_EX}{strip_ansi(line)}{Style.RESET_ALL}")
                    else:
                        print(f"    {line}")
            else:
                print(f"    {Fore.LIGHTBLACK_EX}• No results or not scanned{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")

        print("\n")


    def format_host_output(host, host_protocols):
        lines = []
        lines.append("")  
        lines.append("")  
        lines.append(f"==========Host: {host}==========")
        for protocol in ["SMB", "FTP", "HTTP", "HTTPS", "AV-PORT-DETECTION", "VENDOR-DETECTION"]:
            if protocol == "SMB":
                lines.append("Service: SMB")
            elif protocol == "FTP":
                lines.append("Service: FTP")
            elif protocol in ["HTTP", "HTTPS"]:
                if protocol == "HTTP":
                    lines.append("Service: HTTP/HTTPS")
            elif protocol == "AV-PORT-DETECTION":
                lines.append("AV/EDR/FW Port Detection:")
            elif protocol == "VENDOR-DETECTION":
                lines.append("Vendor Detection:")

            if protocol in host_protocols:
                for line in host_protocols[protocol]:
                    if "No results or not scanned" in line or "No AV/EDR/FW Fingerprint Detected" in line:
                        lines.append(f"    {strip_ansi(line)}")
                    else:
                        lines.append(f"    {strip_ansi(line)}")
            else:
                lines.append("    • No results or not scanned")
            lines.append("─"*35)
        lines.append("")  
        return "\n".join(lines)

    if args.output:
        with open(args.output, 'w') as f:
            f.write("Bōryoku V2 - An Advanced Modular Red Team Tool\n")
            f.write("Author: Dion Mulaj\n")
            f.write("GitHub: https://github.com/dionmulaj\n\n")
            for host in sorted(results.keys()):
                host_protocols = results[host]
                f.write(format_host_output(host, host_protocols))
        print(f"{Fore.YELLOW}[~] Results saved to {args.output}{Style.RESET_ALL}")


    if args.discord:
        webhook_url = None
        webhook_file_path = os.path.join("webhooks", "discord.txt")
        if os.path.exists(webhook_file_path):
            with open(webhook_file_path, "r") as f:
                webhook_url = f.read().strip()

        if webhook_url:
            combined_output = []
            for host in sorted(results.keys()):
                host_protocols = results[host]
                combined_output.append(format_host_output(host, host_protocols))
            final_message = "\n".join(combined_output)
            send_to_discord_webhook(final_message, webhook_url)

    if args.slack:
        slack_config_path = os.path.join("webhooks", "slack.json")
        if os.path.exists(slack_config_path):
            with open(slack_config_path, "r") as f:
                slack_cfg = json.load(f)
                slack_token = slack_cfg.get("bot_token")
                slack_channel = slack_cfg.get("channel_id")
                if slack_token and slack_channel:
                    combined_output = []
                    for host in sorted(results.keys()):
                        host_protocols = results[host]
                        combined_output.append(format_host_output(host, host_protocols))
                    final_message = "\n".join(combined_output)
                    send_message_to_slack(final_message[:40000], slack_token, slack_channel)

if __name__ == "__main__":
    main()