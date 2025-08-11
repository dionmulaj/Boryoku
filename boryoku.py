import sys
import socket
import argparse
import netifaces
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
import subprocess

try:
    from pyvis.network import Network
except ImportError:
    Network = None


init(autoreset=True)

AUTHOR_INFO = f"""
{Fore.CYAN}Bōryoku Framework - V3.0.2
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
    shares_list = []
    files_list = []
    banner = ""

    if stealth:
        stealth_delay()

    max_retries = 3
    success_lines = []
    fail_lines = []
    success = False
    for attempt in range(max_retries):
        try:
            smb = SMBConnection(host, host, sess_port=445, timeout=5)
            smb.login('', '')

            server_name = smb.getServerName()
            banner = server_name or ""
            success_lines.append(f"{Fore.CYAN}[i] SMB Server Name: {server_name}{Style.RESET_ALL}")
            success_lines.append(f"{Fore.GREEN}[+] SMB anonymous login successful on {host}{Style.RESET_ALL}")

            shares = smb.listShares()
            shares_list = [share['shi1_netname'].rstrip('\x00').upper() for share in shares]

            for share in shares:
                share_name = share['shi1_netname'][:-1]

                if stealth:
                    stealth_delay()

                try:
                    entries = smb.listPath(share_name, '*')
                    files_list.extend([entry.get_longname() for entry in entries if entry.get_longname() not in ('.', '..')])
                    success_lines.append(f"{Fore.GREEN}    [+] SMB guest access allowed on share: {share_name}{Style.RESET_ALL}")
                    for entry in entries:
                        name = entry.get_longname()
                        if name not in ('.', '..'):
                            success_lines.append(f"{Fore.WHITE}        - {name}{Style.RESET_ALL}")
                except Exception:
                    success_lines.append(f"{Fore.RED}    [-] Access denied on share: {share_name}{Style.RESET_ALL}")
            smb.close()
            success = True
            break
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(1.5)
                continue
    if not success:
        fail_lines.append(f"{Fore.RED}[-] SMB anonymous login failed on {host}{Style.RESET_ALL}")

    score, details = calculate_honeypot_score("smb", banner, results={"shares": shares_list, "files": files_list})
    verdict_line = honeypot_verdict(score)
    if success:
        success_lines.append(verdict_line)
        if details:
            success_lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
            for d in details:
                success_lines.append(f"  - {d}")
    else:
        fail_lines.append(verdict_line)
        if details:
            fail_lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
            for d in details:
                fail_lines.append(f"  - {d}")

    av_score, av_details = calculate_av_fingerprint("smb", banner, results={"shares": shares_list, "files": files_list})
    if success:
        if av_details:
            success_lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL}{Fore.RED} AV/EDR/FW FINGERPINT DETECTED!!!!!{Style.RESET_ALL}")
            for d in av_details:
                success_lines.append(f"  - {d}")
        else:
            success_lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL} No AV/EDR/FW Fingerprint Detected")
    else:
        if av_details:
            fail_lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL}{Fore.RED} AV/EDR/FW FINGERPINT DETECTED!!!!!{Style.RESET_ALL}")
            for d in av_details:
                fail_lines.append(f"  - {d}")
        else:
            fail_lines.append(f"{Fore.MAGENTA}[Fingerprint Detection]{Style.RESET_ALL} No AV/EDR/FW Fingerprint Detected")

    with output_lock:
        if host not in results:
            results[host] = {}
        if success:
            results[host].setdefault("SMB", []).extend(success_lines)
        else:
            results[host].setdefault("SMB", []).extend(fail_lines)


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

    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=True) as client:
        server_header = "N/A"
        meta_generator = None
        header_error = None
        try:
            root_resp = await client.head(base_url)
            server_header = root_resp.headers.get('Server', 'N/A')
            lines.append(f"{Fore.CYAN}[i] HTTP Server: {server_header}{Style.RESET_ALL}")
        except Exception as e:
            header_error = str(e)
            
            if 'SSLV3_ALERT_HANDSHAKE_FAILURE' in header_error or 'ssl/tls alert handshake failure' in header_error:
                lines.append(f"{Fore.YELLOW}[!] TLS handshake failed for {base_url}. Cannot enumerate HTTPS headers.{Style.RESET_ALL}")
            else:
                
                try:
                    root_get_resp = await client.get(base_url)
                    server_header = root_get_resp.headers.get('Server', 'N/A')
                    lines.append(f"{Fore.CYAN}[i] HTTP Server (GET fallback): {server_header}{Style.RESET_ALL}")
                except Exception as e2:
                    get_error = str(e2)
                    lines.append(f"{Fore.YELLOW}[!] Could not retrieve HTTP(S) headers from {base_url}: {header_error} | GET fallback error: {get_error}{Style.RESET_ALL}")

        
        try:
            root_get_resp = await client.get(base_url)
            html = root_get_resp.text
            meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if meta_match:
                meta_generator = meta_match.group(1)
                lines.append(f"{Fore.CYAN}[i] Meta Generator: {meta_generator}{Style.RESET_ALL}")
        except Exception:
            pass

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

        
        banner_for_scoring = meta_generator if meta_generator else server_header
        score, details = calculate_honeypot_score(protocol, banner_for_scoring, results=responses)
        lines.append(honeypot_verdict(score))
        if details:
            lines.append(f"{Fore.MAGENTA}[Honeypot Details]:{Style.RESET_ALL}")
            for d in details:
                lines.append(f"  - {d}")

        av_score, av_details = calculate_av_fingerprint(protocol, banner_for_scoring)
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
        epilog='Example: python3 boryoku.py -t 192.168.1.0/24 -smb -ftp -http --kerberos --ldap --stealth -o results.txt'
    )

    general_group = parser.add_argument_group('GENERAL OPTIONS')
    general_group.add_argument('-t', required=True, metavar='TARGET', help='Target IP / Range in CIDR (e.g. 192.168.1.25 OR 192.168.1.0/24)')
    general_group.add_argument('-smb', action='store_true', help='Scan for SMB guest access')
    general_group.add_argument('-ftp', action='store_true', help='Scan for FTP anonymous access')
    general_group.add_argument('-http', action='store_true', help='Scan for HTTP(S) critical files')
    general_group.add_argument('-all', action='store_true', help='Scan SMB, FTP, and HTTP(S)')
    general_group.add_argument('--visualize', action='store_true', help='Generate network map visualization')
    general_group.add_argument('-o', '--output', help='Save output to the specified text file')
    general_group.add_argument('--discord', action='store_true', help='Send results to Discord webhook')
    general_group.add_argument('--slack', action='store_true', help='Send results to Slack webhook')


    operational_group = parser.add_argument_group('OPERATIONAL MODES')
    operational_group.add_argument('--stealth', action='store_true', help='Enable stealth mode with randomized packet delays')
    operational_group.add_argument('--anti-virus', action='store_true', help='Detect AV/EDR/FW ports')
    operational_group.add_argument('--cve-check', action='store_true', help='Run CVE check scripts on discovered hosts')
    operational_group.add_argument('--vpn-check', action='store_true', help='Check for VPN endpoints using port patterns')
    operational_group.add_argument('--decoy-http', action='store_true', help='Run HTTP decoy server in background during scan')
    operational_group.add_argument('--decoy-ssh', action='store_true', help='Run SSH decoy server in background during scan')
    operational_group.add_argument('--decoy-ldap', action='store_true', help='Run LDAP decoy server in background during scan')
    operational_group.add_argument('--all-decoys', action='store_true', help='Run all decoy servers (HTTP, SSH, LDAP) in background during scan')


    plugin_group = parser.add_argument_group('PLUGINS')
    plugin_group.add_argument('--kerberos', action='store_true', help='Enable Kerberos plugins')
    plugin_group.add_argument('--ldap', action='store_true', help='Enable LDAP plugins')
    plugin_group.add_argument('--llmnr-nbns', action='store_true', help='Enable LLMNR/NBNS plugins')
    plugin_group.add_argument('--mdns', action='store_true', help='Enable mDNS plugins')
    plugin_group.add_argument('--netbios', action='store_true', help='Enable NetBIOS plugins')
    plugin_group.add_argument('--redis', action='store_true', help='Enable Redis plugins')
    plugin_group.add_argument('--snmp', action='store_true', help='Enable SNMP plugins')
    plugin_group.add_argument('--ssdp-upnp', action='store_true', help='Enable SSDP/UPnP plugins')
    plugin_group.add_argument('--db-enum', action='store_true', help='Enable database enumeration plugins (MySQL, MSSQL, PostgreSQL, Oracle)')
    plugin_group.add_argument('--docker-k8s', action='store_true', help='Enable Docker/Kubernetes API detection plugins')
    plugin_group.add_argument('--ics-scada', action='store_true', help='Enable ICS/SCADA protocol detection plugins (Modbus, DNP3, BACnet, S7comm)')
    plugin_group.add_argument('--all-plugins', action='store_true', help='Enable all plugins in arsenal/*/')

    args = parser.parse_args()
    stealth_enabled = args.stealth
    anti_virus_enabled = args.anti_virus

    
    if anti_virus_enabled:
        av_ports = load_av_ports()
        common_ports = av_ports
    else:
        common_ports = {}

    
    vpn_ports = {}
    if getattr(args, 'vpn_check', False):
        vpn_path = os.path.join(os.path.dirname(__file__), "signatures", "vpn-check.json")
        try:
            with open(vpn_path, "r") as f:
                vpn_ports = json.load(f).get("vpn_ports", {})
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not load vpn-check.json: {e}{Style.RESET_ALL}")

    
    
    if not any([args.smb, args.ftp, args.http, args.all, args.anti_virus, args.vpn_check]):
        print(f"{Fore.RED}[-] You must specify at least one scan mode: -smb, -ftp, -http, -all, --anti-virus, or --vpn-check")
        return

    import socket
    try:
        ip_list = [str(ip) for ip in ip_network(args.t, strict=False)]
    except ValueError:
        print(f"{Fore.RED}[-] Invalid CIDR range")
        return
    
    local_ips = set()
    
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                for addr in addrs.get(family, []):
                    ip = addr.get('addr')
                    if ip:
                        local_ips.add(ip)
    except Exception:
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    
    local_ips.add('127.0.0.1')
    local_ips.add('::1')
    
    ip_list = [ip for ip in ip_list if ip not in local_ips]

    scan_smb = args.smb or args.all
    scan_ftp = args.ftp or args.all
    scan_http = args.http or args.all

    
    if args.vpn_check and not any([scan_smb, scan_ftp, scan_http, args.anti_virus]):
        
        try:
            ip_list = [str(ip) for ip in ip_network(args.t, strict=False)]
        except ValueError:
            print(f"{Fore.RED}[-] Invalid CIDR range")
            return
        
        vpn_path = os.path.join(os.path.dirname(__file__), "signatures", "vpn-check.json")
        vpn_ports = {}
        try:
            with open(vpn_path, "r") as f:
                vpn_ports = json.load(f).get("vpn_ports", {})
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not load vpn-check.json: {e}{Style.RESET_ALL}")
        ports_to_check = [int(p) for p in vpn_ports.keys()]
        open_hosts = {port: [] for port in ports_to_check}
        print(f"{Fore.MAGENTA}[~] Initiating VPN endpoint scan...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_ip_port = {
                executor.submit(is_port_open, ip, port): (ip, port)
                for ip in ip_list for port in ports_to_check
            }
            futures = list(future_to_ip_port.keys())
            with tqdm(total=len(futures), desc="Scanning for VPN ports") as pbar:
                for future in as_completed(futures):
                    ip, port = future_to_ip_port[future]
                    if future.result():
                        open_hosts[port].append(ip)
                    pbar.update(1)
        host_ports = {}
        for port, hosts in open_hosts.items():
            for host in hosts:
                host_ports.setdefault(host, []).append(port)
        
        for host, ports in host_ports.items():
            detected = []
            for port in set(ports):
                port_str = str(port)
                if port_str in vpn_ports:
                    detected.append(f"{port} ({vpn_ports[port_str]})")
            if detected:
                vpn_line = f"{Fore.CYAN}[VPN Endpoint Detected] {host} => {', '.join(detected)}{Style.RESET_ALL}"
                if host not in results:
                    results[host] = {}
                results[host].setdefault("VPN-ENDPOINT", []).append(vpn_line)
        
        for host in sorted(results.keys()):
            print("\n\n")
            print(f"{Fore.CYAN}==========Host: {host}=========={Style.RESET_ALL}")
            host_protocols = results[host]
            if "VPN-ENDPOINT" in host_protocols:
                print(f"{Fore.YELLOW}VPN Endpoint Detection:{Style.RESET_ALL}")
                for line in host_protocols["VPN-ENDPOINT"]:
                    print(f"    {line}")
                print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.LIGHTBLACK_EX}• No VPN endpoints detected{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")
        
        def format_vpn_output(host, host_protocols):
            lines = []
            lines.append("")
            lines.append("")
            lines.append(f"==========Host: {host}==========")
            lines.append("VPN Endpoint Detection:")
            if "VPN-ENDPOINT" in host_protocols:
                for line in host_protocols["VPN-ENDPOINT"]:
                    lines.append(f"    {strip_ansi(line)}")
            else:
                lines.append("    • No VPN endpoints detected")
            lines.append("─"*35)
            lines.append("")
            return "\n".join(lines)
        if args.output:
            with open(args.output, 'w') as f:
                f.write("Bōryoku Framework - V3.0.2\n")
                f.write("Author: Dion Mulaj\n")
                f.write("GitHub: https://github.com/dionmulaj\n\n")
                for host in sorted(results.keys()):
                    host_protocols = results[host]
                    f.write(format_vpn_output(host, host_protocols))
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
                    combined_output.append(format_vpn_output(host, host_protocols))
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
                            combined_output.append(format_vpn_output(host, host_protocols))
                        final_message = "\n".join(combined_output)
                        send_message_to_slack(final_message[:40000], slack_token, slack_channel)
        return



    
    import queue
    decoy_logs = queue.Queue()
    decoy_threads = []

    def run_decoy(decoy_type, log_queue):
        import importlib.util
        import os
        decoy_map = {
            'http': 'decoy/http_decoy.py',
            'ssh': 'decoy/ssh_decoy.py',
            'ldap': 'decoy/ldap_decoy.py',
        }
        script_path = decoy_map.get(decoy_type)
        if not script_path or not os.path.exists(script_path):
            return
        spec = importlib.util.spec_from_file_location(f"{decoy_type}_decoy", script_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'run_decoy_server'):
            
            if decoy_type == 'ssh':
                mod.run_decoy_server(log_queue, port=22)
            elif decoy_type == 'ldap':
                mod.run_decoy_server(log_queue, port=389)
            else:
                mod.run_decoy_server(log_queue)

    
    if getattr(args, 'all_decoys', False):
        setattr(args, 'decoy_http', True)
        setattr(args, 'decoy_ssh', True)
        setattr(args, 'decoy_ldap', True)

    if getattr(args, 'decoy_http', False):
        print(f"{Fore.MAGENTA}[Info - Decoy]{Style.RESET_ALL} Starting HTTP decoy server...")
        t = threading.Thread(target=run_decoy, args=('http', decoy_logs), daemon=True)
        t.start()
        decoy_threads.append(t)
    if getattr(args, 'decoy_ssh', False):
        print(f"{Fore.MAGENTA}[Info - Decoy]{Style.RESET_ALL} Starting SSH decoy server...")
        t = threading.Thread(target=run_decoy, args=('ssh', decoy_logs), daemon=True)
        t.start()
        decoy_threads.append(t)
    if getattr(args, 'decoy_ldap', False):
        print(f"{Fore.MAGENTA}[Info - Decoy]{Style.RESET_ALL} Starting LDAP decoy server...")
        t = threading.Thread(target=run_decoy, args=('ldap', decoy_logs), daemon=True)
        t.start()
        decoy_threads.append(t)



    
    import importlib.util
    import glob
    arsenal_dir = os.path.join(os.path.dirname(__file__), "arsenal")
    plugin_group_map = {
        'kerberos': 'kerberos',
        'ldap': 'ldap',
        'llmnr-nbns': 'llmnr-nbns',
        'mdns': 'mdns',
        'netbios': 'netbios',
        'redis': 'redis',
        'snmp': 'snmp',
        'ssdp-upnp': 'ssdp-upnp',
        'db-enum': 'db-enum',
        'docker-k8s': 'docker-k8s',
        'ics-scada': 'ics-scada',
    }
    
    cve_check_group_map = {
        'web': 'web',
        'network': 'network'
    }
    cve_check_dir = os.path.join(os.path.dirname(__file__), "cve-check")
    selected_cve_groups = list(cve_check_group_map.keys()) 

    cve_check_files = []
    for group in selected_cve_groups:
        group_dir = os.path.join(cve_check_dir, cve_check_group_map[group])
        group_scripts = glob.glob(os.path.join(group_dir, "*.py"))
        for script_path in group_scripts:
            script_name = os.path.splitext(os.path.basename(script_path))[0]
            if script_name.startswith("_"):
                continue
            cve_check_files.append(script_path)

    def run_cve_checks_for_host(host, results):
        for script_path in cve_check_files:
            script_name = os.path.splitext(os.path.basename(script_path))[0]
            spec = importlib.util.spec_from_file_location(script_name, script_path)
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    mod.run(host, results)
            except Exception as e:
                results[host].setdefault("CVE-CHECK", []).append(f"Error running {script_name}: {e}")

    selected_groups = []
    if args.all_plugins:
        selected_groups = list(plugin_group_map.keys())
    else:
        for group in plugin_group_map:
            if getattr(args, group.replace('-', '_')):
                selected_groups.append(group)

    plugin_files = []
    plugin_ports = set()
    for group in selected_groups:
        group_dir = os.path.join(arsenal_dir, plugin_group_map[group])
        group_plugins = glob.glob(os.path.join(group_dir, "*.py"))
        for plugin_path in group_plugins:
            plugin_name = os.path.splitext(os.path.basename(plugin_path))[0]
            if plugin_name.startswith("_"):
                continue
            plugin_files.append(plugin_path)
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "PORTS") and isinstance(mod.PORTS, (list, tuple, set)):
                        plugin_ports.update(int(p) for p in mod.PORTS)
                except Exception:
                    pass

    ports_to_check = []
    if scan_smb:
        ports_to_check.append(445)
    if scan_ftp:
        ports_to_check.append(21)
    if scan_http:
        ports_to_check.extend([80, 443])
    if anti_virus_enabled:
        ports_to_check.extend([int(p) for p in common_ports.keys() if int(p) not in ports_to_check])
    
    if vpn_ports:
        for p in vpn_ports.keys():
            try:
                port_int = int(p)
                if port_int not in ports_to_check:
                    ports_to_check.append(port_int)
            except Exception:
                continue

    
    for p in plugin_ports:
        if p not in ports_to_check:
            ports_to_check.append(p)

    open_hosts = {port: [] for port in ports_to_check}

    print(f"{Fore.MAGENTA}[~] Initiating the scan...{Style.RESET_ALL}")
    open_ports_messages = []

    with ThreadPoolExecutor(max_workers=100) as executor:
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

    
    if getattr(args, 'vpn_check', False) and vpn_ports:
        for host, ports in host_ports.items():
            detected = []
            for port in set(ports):
                port_str = str(port)
                if port_str in vpn_ports:
                    detected.append(f"{port} ({vpn_ports[port_str]})")
            if detected:
                vpn_line = f"{Fore.CYAN}[VPN Endpoint Detected] {host} => {', '.join(detected)}{Style.RESET_ALL}"
                if host not in results:
                    results[host] = {}
                results[host].setdefault("VPN-ENDPOINT", []).append(vpn_line)


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

    max_workers_smb = min(8, len(smb_hosts)) or 1
    max_workers_ftp = min(25, len(ftp_hosts)) or 1
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
        print(f"{Fore.MAGENTA}[~] Enumerating web applications...{Style.RESET_ALL}")
        hosts_http = open_hosts.get(80, [])
        hosts_https = open_hosts.get(443, [])
        run_async_http_scans(hosts_http, hosts_https, stealth_enabled)

    
    vendor_db = load_vendor_fingerprints()

    def get_mac_address(ip):
        try:
            subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            pid = subprocess.Popen(["arp", "-n", ip], stdout=subprocess.PIPE)
            s = pid.communicate()[0].decode()

            match = re.search(r"at ([0-9a-fA-F:]{17}) ", s)
            if match:
                return match.group(1)
            
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

    
    if args.cve_check:
        print(f"{Fore.MAGENTA}[~] Running CVE checks on discovered hosts...{Style.RESET_ALL}")
        hosts_list = sorted(results.keys())
        def cve_worker(host):
            run_cve_checks_for_host(host, results)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(cve_worker, host) for host in hosts_list]
            for _ in tqdm(as_completed(futures), total=len(futures), desc="Checking for vulnerabilities"):
                pass



    
    loaded_plugins = []  
    for plugin_path in plugin_files:
        plugin_name = os.path.splitext(os.path.basename(plugin_path))[0]
        if plugin_name.startswith("_"):
            continue  
        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    ports = set()
                    if hasattr(mod, "PORTS") and isinstance(mod.PORTS, (list, tuple, set)):
                        ports = set(int(p) for p in mod.PORTS)
                    loaded_plugins.append((mod, ports))
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to load plugin {plugin_name}: {e}{Style.RESET_ALL}")

    if loaded_plugins:
        print(f"{Fore.MAGENTA}[~] Running plugins on discovered hosts...{Style.RESET_ALL}")
        plugin_tasks = []
        with ThreadPoolExecutor(max_workers=75) as executor:
            for plugin, plugin_ports in loaded_plugins:
                relevant_hosts = set()
                for host, ports in host_ports.items():
                    if plugin_ports and any(p in ports for p in plugin_ports):
                        relevant_hosts.add(host)
                
                if not plugin_ports:
                    relevant_hosts = set(results.keys())
                for host in sorted(relevant_hosts):
                    plugin_tasks.append(executor.submit(plugin.run, host, results))
            
            with tqdm(total=len(plugin_tasks), desc="Running Plugins") as pbar:
                for future in as_completed(plugin_tasks):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Plugin execution failed: {e}{Style.RESET_ALL}")
                    pbar.update(1)


    for host in sorted(results.keys()):
        print("\n\n")
        print(f"{Fore.CYAN}==========Host: {host}=========={Style.RESET_ALL}")
        host_protocols = results[host]

        for protocol in ["SMB", "FTP", "HTTP", "HTTPS", "AV-PORT-DETECTION", "VENDOR-DETECTION", "VPN-ENDPOINT", "CVE-CHECK"]:
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
            elif protocol == "VPN-ENDPOINT":
                print(f"{Fore.YELLOW}VPN Endpoint Detection:{Style.RESET_ALL}")
            elif protocol == "CVE-CHECK":
                print(f"{Fore.YELLOW}CVE Checks:{Style.RESET_ALL}")

            if protocol in host_protocols:
                for line in host_protocols[protocol]:
                    if "No results or not scanned" in line or "No AV/EDR/FW Fingerprint Detected" in line:
                        print(f"    {Fore.LIGHTBLACK_EX}{strip_ansi(line)}{Style.RESET_ALL}")
                    else:
                        print(f"    {line}")
            else:
                print(f"    {Fore.LIGHTBLACK_EX}• No results or not scanned{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")


        plugin_keys = [k for k in host_protocols if k.startswith("PLUGIN")] 
        if plugin_keys:
            print(f"{Fore.YELLOW}Plugin Output:{Style.RESET_ALL}")
            for key in sorted(plugin_keys):
                print(f"    {Fore.YELLOW}[{key}]{Style.RESET_ALL}")
                for line in host_protocols[key]:
                    print(f"        {line}")
            print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Plugin Output:{Style.RESET_ALL}")
            print(f"    {Fore.LIGHTBLACK_EX}• No plugin results{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─'*35}{Style.RESET_ALL}")

        print("\n")

    
    if getattr(args, 'decoy_http', False) or getattr(args, 'decoy_ssh', False) or getattr(args, 'decoy_ldap', False):
        time.sleep(2)
        print(f"{Fore.MAGENTA}\n========== Decoy Interactions =========={Style.RESET_ALL}")
        seen = set()
        found = False
        decoy_entries = []
        while not decoy_logs.empty():
            entry = decoy_logs.get()
            decoy_entries.append(entry)
            ip = entry.get('ip')
            action = entry.get('action')
            if ip and action:
                key = (ip, action)
                if key not in seen:
                    if 'SSH' in action:
                        decoy_type = 'SSH'
                    elif 'LDAP' in action:
                        decoy_type = 'LDAP'
                    else:
                        decoy_type = 'HTTP'
                    print(f"{Fore.MAGENTA}[{decoy_type} - Decoy]{Style.RESET_ALL} {ip} tried: {action}")
                    seen.add(key)
                    found = True

        for entry in decoy_entries:
            decoy_logs.put(entry)
        if not found:
            print(f"    {Fore.LIGHTBLACK_EX}• No results or not scanned{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*40}{Style.RESET_ALL}")
        print("\n\n")
        



    def get_decoy_interactions_text():
        lines = []
        lines.append("")
        lines.append(f"========== Decoy Interactions ==========")
        seen = set()
        time.sleep(2)
        decoy_items = []
        try:
            import queue as _queue
            while True:
                entry = decoy_logs.get_nowait()
                decoy_items.append(entry)
        except Exception:
            pass
        
        for entry in decoy_items:
            decoy_logs.put(entry)
        
        for entry in decoy_items:
            ip = entry.get('ip')
            action = entry.get('action')
            if ip and action:
                key = (ip, action)
                if key not in seen:
                    lines.append(f"[HTTP - Decoy] {ip} tried: {action}")
                    seen.add(key)
        if len(lines) == 2:  
            lines.append("• No results or not scanned")
        lines.append("="*40)
        lines.append("")
        lines.append("")
        return "\n".join(lines)

    def format_host_output(host, host_protocols):
        lines = []
        lines.append("")  
        lines.append("")  
        lines.append(f"==========Host: {host}==========")
        for protocol in ["SMB", "FTP", "HTTP", "HTTPS", "AV-PORT-DETECTION", "VENDOR-DETECTION", "VPN-ENDPOINT", "CVE-CHECK"]:
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

            elif protocol == "VPN-ENDPOINT":
                lines.append("VPN Endpoint Detection:")
            elif protocol == "CVE-CHECK":
                lines.append("CVE Checks:")

            if protocol in host_protocols:
                for line in host_protocols[protocol]:
                    if "No results or not scanned" in line or "No AV/EDR/FW Fingerprint Detected" in line:
                        lines.append(f"    {strip_ansi(line)}")
                    else:
                        lines.append(f"    {strip_ansi(line)}")
            else:
                lines.append("    • No results or not scanned")
            lines.append("─"*35)

        
        plugin_keys = [k for k in host_protocols if k.startswith("PLUGIN")]
        if plugin_keys:
            lines.append("Plugin Output:")
            for key in sorted(plugin_keys):
                lines.append(f"    [{key}]")
                for line in host_protocols[key]:
                    lines.append(f"        {strip_ansi(line)}")
            lines.append("─"*35)
        else:
            lines.append("Plugin Output:")
            lines.append("    • No plugin results")
            lines.append("─"*35)

        lines.append("")  
        return "\n".join(lines)

    if args.output:
        with open(args.output, 'w') as f:
            f.write("Bōryoku Framework - V3.0.2\n")
            f.write("Author: Dion Mulaj\n")
            f.write("GitHub: https://github.com/dionmulaj\n\n")
            for host in sorted(results.keys()):
                host_protocols = results[host]
                f.write(format_host_output(host, host_protocols))
            
            if getattr(args, 'decoy_http', False) or getattr(args, 'decoy_ssh', False) or getattr(args, 'decoy_ldap', False):
                f.write(get_decoy_interactions_text())
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
            
            if getattr(args, 'decoy_http', False) or getattr(args, 'decoy_ssh', False) or getattr(args, 'decoy_ldap', False):
                combined_output.append(get_decoy_interactions_text())
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
                    
                    if getattr(args, 'decoy_http', False) or getattr(args, 'decoy_ssh', False) or getattr(args, 'decoy_ldap', False):
                        combined_output.append(get_decoy_interactions_text())
                    final_message = "\n".join(combined_output)
                    send_message_to_slack(final_message[:40000], slack_token, slack_channel)

    
    if args.visualize:
        if Network is None:
            print(f"{Fore.RED}[!] pyvis is not installed. Run 'pip install pyvis' to use visualization.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] Generating network map visualization...{Style.RESET_ALL}")
            build_and_show_network_graph(results)


def build_and_show_network_graph(results):
    from datetime import datetime
    import json as _json
    net = Network(height="750px", width="100%", directed=False, layout=None)
    host_info_map = {}
    
    node_styles = {
        "host": {"color": "#4F8EF7", "shape": "ellipse", "icon": "🖥️"},
        "SMB": {"color": "#FFD700", "icon": "📁"},
        "FTP": {"color": "#FF8C00", "icon": "📦"},
        "HTTP": {"color": "#32CD32", "icon": "🌐"},
        "HTTPS": {"color": "#228B22", "icon": "🔒"},
        "AV-PORT-DETECTION": {"color": "#DC143C", "icon": "🛡️"},
        "VENDOR-DETECTION": {"color": "#8A2BE2", "icon": "🏷️"},
        "VPN-ENDPOINT": {"color": "#00CED1", "icon": "🔑"},
        "CVE-CHECK": {"color": "#B22222", "icon": "⚠️"},
        "PLUGIN": {"color": "#FF69B4", "icon": "🔌"},
    }
    
    total_hosts = len(results)
    total_services = set()
    total_vpn = 0
    total_av = 0
    total_honeypot = 0
    import re
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mK]')
    for host, protocols in results.items():
        info_lines = []
        for proto, details in protocols.items():
            total_services.add(proto)

            for line in details:
                if "HONEYPOT DETECTED" in line:
                    total_honeypot += 1
                if proto == "VPN-ENDPOINT":
                    total_vpn += 1
                if proto == "AV-PORT-DETECTION":
                    total_av += 1
        
        info_lines.append("<table style='width:100%;border-collapse:collapse;'>")
        for proto, details in protocols.items():
            style = node_styles.get(proto, node_styles.get("PLUGIN", {"color": "#FF69B4", "icon": "🔌"}))
            info_lines.append(f"<tr><td style='background:{style['color']};font-weight:bold;padding:4px;border:1px solid #ccc;'>{style['icon']} {proto}</td></tr>")
            for line in details:
                clean_line = ansi_escape.sub('', line)
                info_lines.append(f"<tr><td style='padding:4px;border:1px solid #eee;'>{clean_line}</td></tr>")
        info_lines.append("</table>")
        info_html = "".join(info_lines)
        host_info_map[host] = info_html
        
        net.add_node(host, label=f"{node_styles['host']['icon']} {host}", color=node_styles['host']['color'], title="Click for details", group="host", shape=node_styles['host']['shape'], level=1)
        
        for proto in protocols:
            style = node_styles.get(proto, node_styles.get("PLUGIN", {"color": "#FF69B4", "icon": "🔌"}))
            net.add_node(proto, label=f"{style['icon']} {proto}", color=style['color'], group=proto, level=2)
            
            edge_style = {"color": style['color'], "width": 2}
            if proto == "VPN-ENDPOINT":
                edge_style["dashes"] = True
            elif proto == "AV-PORT-DETECTION":
                edge_style["width"] = 3
            net.add_edge(host, proto, **edge_style)
    
    legend_html = "<b>Legend:</b><br>" + "<br>".join([
        f"<span style='color:{v['color']};font-weight:bold;'>{v['icon']} {k}</span>" for k, v in node_styles.items() if k != "host"
    ])
    net.add_node("Legend", label="Legend", color="#333", shape="box", title=legend_html, group="legend", level=0)
    
    existing_nodes = set(net.get_nodes())
    for proto in total_services:
        if proto in existing_nodes:
            net.add_edge("Legend", proto, color="#333", width=1, dashes=True)
    
    summary_html = f"<b>Scan Summary</b><br>Total Hosts: {total_hosts}<br>Total Services: {len(total_services)}<br>VPN Endpoints: {total_vpn}<br>AV/EDR/FW Detected: {total_av}<br>Honeypots: {total_honeypot}" 
    net.add_node("Summary", label="Summary", color="#222", shape="ellipse", title=summary_html, group="summary", level=0)
    net.add_edge("Summary", "Legend", color="#222", width=1)
    
    now = datetime.now()
    filename = now.strftime("%d.%m.%Y-%H.%M.html")
    mapping_dir = os.path.join(os.path.dirname(__file__), "mapping")
    if not os.path.exists(mapping_dir):
        os.makedirs(mapping_dir)
    output_html = os.path.join(mapping_dir, filename)
    
    net.set_options('{"layout": {"hierarchical": {"enabled": true, "direction": "UD", "sortMethod": "hubsize", "nodeSpacing": 200, "treeSpacing": 400, "levelSeparation": 250}}, "physics": {"hierarchicalRepulsion": {"nodeDistance": 250}, "stabilization": {"enabled": true, "iterations": 200}}}')
    net.show(output_html, notebook=False)
    
    try:
        with open(output_html, "r", encoding="utf-8") as f:
            html = f.read()

        modal_code = '''
<style>
  #hostInfoModal { display:none; position:fixed; z-index:9999; left:0; top:0; width:100vw; height:100vh; background:rgba(0,0,0,0.5); }
  #hostInfoModal .modal-content { background:#fff; margin:10vh auto; padding:20px; border-radius:8px; width:80vw; max-width:600px; max-height:70vh; overflow-y:auto; }
  #hostInfoModal .close { float:right; font-size:28px; font-weight:bold; cursor:pointer; }
  #searchBar { margin:10px 0; padding:8px; width:40vw; font-size:16px; border-radius:4px; border:1px solid #ccc; }
</style>
<div id="hostInfoModal">
  <div class="modal-content">
    <span class="close" onclick="document.getElementById('hostInfoModal').style.display='none'">&times;</span>
    <div id="hostInfoDetails"></div>
  </div>
</div>
<input id="searchBar" type="text" placeholder="Search host or service..." oninput="filterNodes()" />
'''
        
        host_info_js = f"var hostInfoMap = {_json.dumps(host_info_map)};"
        js_code = f'''
<script type="text/javascript">
{host_info_js}
var network;
function setupHostClick() {{
  if (!window.network) return;
  network.on("click", function(params) {{
    if (params.nodes.length > 0) {{
      var nodeId = params.nodes[0];
      if (hostInfoMap[nodeId]) {{
        document.getElementById('hostInfoDetails').innerHTML = hostInfoMap[nodeId];
        document.getElementById('hostInfoModal').style.display = 'block';
      }}
    }}
  }});
}}
function filterNodes() {{
  var val = document.getElementById('searchBar').value.toLowerCase();
  var allNodes = network.body.data.nodes.get();
  var update = allNodes.map(function(n) {{
    if (n.label.toLowerCase().includes(val)) {{
      return {{id: n.id, hidden: false}};
    }} else {{
      return {{id: n.id, hidden: true}};
    }}
  }});
  network.body.data.nodes.update(update);
}}
window.addEventListener('load', function() {{
  network = window.network;
  setupHostClick();
}});
</script>
'''
        
        html = html.replace("</body>", modal_code + js_code + "</body>")
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        print(f"[!] Failed to inject click modal: {e}")

if __name__ == "__main__":
    main()
