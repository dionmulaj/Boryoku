"""
Detects exposed Docker/Kubernetes APIs and enumerates containers if possible.
"""

PORTS = [2375, 2376, 6443, 10250, 10255]  

import requests
from colorama import Fore, Style

def run(host, results, **kwargs):
    output = []
    
    for port in [2375, 2376]:
        url = f"http://{host}:{port}/containers/json"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200 and isinstance(resp.json(), list):
                output.append(f"{Fore.GREEN}[+] Docker API open on {host}:{port} - Containers: {len(resp.json())}{Style.RESET_ALL}")
                for c in resp.json():
                    output.append(f"    - Container: {c.get('Names', ['?'])[0]} (ID: {c.get('Id', '?')[:12]})")
            elif resp.status_code == 200:
                output.append(f"{Fore.YELLOW}[?] Docker API open on {host}:{port} but no containers listed{Style.RESET_ALL}")
        except Exception:
            pass
    
    url = f"https://{host}:6443/version"
    try:
        resp = requests.get(url, timeout=3, verify=False)
        if resp.status_code == 200:
            output.append(f"{Fore.GREEN}[+] Kubernetes API open on {host}:6443 - Version: {resp.json().get('gitVersion', '?')}{Style.RESET_ALL}")
    except Exception:
        pass
    
    for port in [10250, 10255]:
        url = f"http://{host}:{port}/pods"
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200 and 'items' in resp.json():
                output.append(f"{Fore.GREEN}[+] Kubelet open on {host}:{port} - Pods: {len(resp.json()['items'])}{Style.RESET_ALL}")
                for pod in resp.json()['items']:
                    output.append(f"    - Pod: {pod.get('metadata', {}).get('name', '?')}")
            elif resp.status_code == 200:
                output.append(f"{Fore.YELLOW}[?] Kubelet open on {host}:{port} but no pods listed{Style.RESET_ALL}")
        except Exception:
            pass
    if output:
        if host not in results:
            results[host] = {}
        results[host].setdefault("PLUGIN-Docker-K8s", []).extend(output)
