
from http.server import HTTPServer, BaseHTTPRequestHandler


import random
import string
from http.server import HTTPServer, BaseHTTPRequestHandler

class LoggingHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/log':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                import json
                data = json.loads(post_data.decode())
                if self.log_queue:
                    entry = {'ip': self.client_address[0], 'action': f'JS Info: {data}'}
                    self.log_queue.put(entry)
            except Exception:
                pass
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    log_queue = None

    def do_GET(self):
        if self.log_queue:
            entry = {'ip': self.client_address[0], 'action': f'HTTP GET {self.path}'}
            self.log_queue.put(entry)

        banners = [
            "Welcome to Internal Portal",
            "Company Intranet",
            "Secure File Share",
            "Web Management Console",
            "Device Control Panel",
            "Login Required",
            "Dashboard",
            "Service Status Page",
            "System Monitor",
            "User Portal",
            "Internal HR Portal",
            "Finance Dashboard",
            "Employee Self-Service",
            "Remote Access Gateway",
            "VPN Management Console",
            "IT Helpdesk",
            "Project Management",
            "Asset Inventory",
            "Compliance Center",
            "Incident Response Portal",
            "Network Operations Center",
            "Secure Messaging",
            "Document Repository",
            "Cloud Resource Manager",
            "DevOps Pipeline",
            "QA Test Environment",
            "Legacy System Console",
            "Partner Portal",
            "Customer Support Center",
            "IoT Device Hub",
            "Backup & Restore",
            "Data Analytics Platform"
        ]
        random_banner = random.choice(banners)


        server_headers = [
            "nginx/1.18.0",
            "nginx/1.21.6",
            "nginx/1.23.3",
            "Apache/2.4.41 (Ubuntu)",
            "Apache/2.4.54 (Debian)",
            "Apache/2.2.34 (Unix)",
            "Microsoft-IIS/10.0",
            "Microsoft-IIS/8.5",
            "Caddy",
            "lighttpd/1.4.55",
            "lighttpd/1.4.65",
            "OpenResty/1.19.3.1",
            "OpenResty/1.21.4.1",
            "gunicorn/20.1.0",
            "gunicorn/19.9.0",
            "Jetty(9.4.35.v20201120)",
            "Jetty(10.0.7)",
            "GWS",
            "cloudflare",
            "Oracle-Application-Server-11g",
            "IBM_HTTP_Server/8.5.5.16",
            "Cherokee/1.2.104",
            "Tengine/2.3.2",
            "LiteSpeed",
            "Varnish",
            "AkamaiGHost",
            "Sucuri/Cloudproxy",
            "BarracudaHTTP 3.1",
            "NetScaler",
            "F5 BIG-IP",
            "AWSALB"
        ]
        random_server = random.choice(server_headers)


        messages = [
            "All systems operational.",
            "Please login to continue.",
            "No new notifications.",
            "Maintenance scheduled for Sunday.",
            "Unauthorized access is prohibited.",
            "Contact IT support for help.",
            "Session expired. Please re-authenticate.",
            "Welcome, user!",
            "System update available.",
            "Your connection is secure.",
            "You have 2 unread messages.",
            "Password will expire in 5 days.",
            "New device detected on your account.",
            "Multi-factor authentication required.",
            "Your last login was from a new location.",
            "System will reboot at midnight.",
            "Your access level: Standard User.",
            "Admin privileges required for this action.",
            "License key validated successfully.",
            "Backup completed successfully.",
            "Critical update pending installation.",
            "Your session will timeout in 10 minutes.",
            "Unexpected error occurred. Please try again.",
            "Your account is locked. Contact administrator.",
            "Welcome to the secure area.",
            "You have been logged out due to inactivity.",
            "System resources are within normal range.",
            "Your request has been submitted.",
            "No scheduled tasks at this time.",
            "Data synchronization in progress."
        ]
        random_message = random.choice(messages)

        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=24))

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', random_server)
        self.send_header('Set-Cookie', f'sessionid={session_id}; HttpOnly')
        self.end_headers()
        html = f"""
        <html><head><title>{random_banner}</title></head>
        <body>
            <h1>{random_banner}</h1>
            <p>{random_message}</p>
            <script>
            (function() {{
                var data = {{
                    platform: navigator.platform,
                    language: navigator.language,
                    screen: [screen.width, screen.height, screen.colorDepth]
                }};
                try {{
                    fetch('/log', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify(data)
                    }});
                }} catch(e) {{}}
            }})();
            </script>
        </body></html>
        """
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  

def run_decoy_server(log_queue, host="0.0.0.0", port=80):
    import warnings
    warnings.filterwarnings("ignore")
    LoggingHTTPRequestHandler.log_queue = log_queue
    server = HTTPServer((host, port), LoggingHTTPRequestHandler)
    server.serve_forever()

if __name__ == "__main__":
    import queue
    q = queue.Queue()
    run_decoy_server(q)
