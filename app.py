from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import dns.resolver
import time
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='threading')

class AdvancedWebScanner:
    def __init__(self, target_url, root_domain=None):
        self.target_url = target_url
        self.root_domain = root_domain or urlparse(target_url).netloc
        self.vulnerabilities = []
        self.scanning = True
        self.session = requests.Session()
        
        # Enhanced payload database
        self.payloads = {
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "\"><script>alert(1)</script>"
            ],
            'sql': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT null,username,password FROM users--",
                "' OR SLEEP(5)--"
            ],
            'sensitive_paths': [
                '/.env', '/config.php', '/.git/config',
                '/wp-config.php', '/backup.zip',
                '/phpinfo.php', '/.aws/credentials'
            ],
            'common_subdomains': [
                'dev', 'staging', 'test', 'api',
                'admin', 'secure', 'portal'
            ],
            'auth_bypass': [
                {'username': 'admin', 'password': 'admin'},
                {'username': "' OR '1'='1'--", 'password': ''},
                {'admin': 'true', 'bypass': '1'}
            ]
        }
        
        # Regex patterns for sensitive data
        self.sensitive_patterns = {
            'API Keys': r'(?i)(api_key|api-key|apikey)[=:]\s*[\'"]?([a-z0-9]{32,45})[\'"]?',
            'AWS Keys': r'(?i)(aws_access_key_id|aws_secret_access_key)[=:]\s*[\'"]?([a-z0-9/+]{40})[\'"]?',
            'Database Creds': r'(?i)(db_|database_)(user|name|pass|host)[=:]\s*[\'"]?([^\s\'"]+)[\'"]?',
            'Auth Tokens': r'(?i)(token|secret|auth)[=:]\s*[\'"]?([a-z0-9]{32,128})[\'"]?'
        }

    def update_status(self, message):
        socketio.emit('status_update', {'message': message, 'timestamp': datetime.now().isoformat()})

    def report_finding(self, vuln_type, details, payload, severity='Medium'):
        finding = {
            'type': vuln_type,
            'details': details,
            'payload': payload,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(finding)
        socketio.emit('new_finding', finding)
        return finding

    # Vulnerability Checks
    def check_xss(self):
        self.update_status("Checking for XSS vulnerabilities...")
        for payload in self.payloads['xss']:
            if not self.scanning: return
            try:
                test_url = f"{self.target_url}?q={payload}"
                res = self.session.get(test_url, timeout=10)
                if payload in res.text:
                    self.report_finding(
                        'Cross-Site Scripting (XSS)',
                        f"Reflected payload in response: {payload}",
                        test_url,
                        'High'
                    )
            except Exception as e:
                self.update_status(f"XSS check error: {str(e)}")

    def check_sqli(self):
        self.update_status("Checking for SQL Injection...")
        for payload in self.payloads['sql']:
            if not self.scanning: return
            try:
                test_url = f"{self.target_url}?id={payload}"
                start_time = time.time()
                res = self.session.get(test_url, timeout=10)
                
                # Time-based detection
                if time.time() - start_time > 5 and "' OR SLEEP" in payload:
                    self.report_finding(
                        'SQL Injection (Time-Based)',
                        f"Time delay detected with payload: {payload}",
                        test_url,
                        'Critical'
                    )
                # Error-based detection
                elif any(err in res.text.lower() for err in ['mysql', 'syntax', 'sql']):
                    self.report_finding(
                        'SQL Injection (Error-Based)',
                        f"Database error with payload: {payload}",
                        test_url,
                        'Critical'
                    )
            except Exception as e:
                self.update_status(f"SQLi check error: {str(e)}")

    def check_sensitive_data(self):
        self.update_status("Checking for sensitive data exposure...")
        for path in self.payloads['sensitive_paths']:
            if not self.scanning: return
            try:
                full_url = urljoin(self.target_url, path)
                res = self.session.get(full_url, timeout=8)
                
                if res.status_code == 200:
                    # Check for sensitive patterns
                    for data_type, pattern in self.sensitive_patterns.items():
                        matches = re.findall(pattern, res.text)
                        if matches:
                            self.report_finding(
                                'Sensitive Data Exposure',
                                f"Exposed {data_type} in {path}",
                                full_url,
                                'High'
                            )
                    
                    # General sensitive file detection
                    self.report_finding(
                        'Sensitive File Exposure',
                        f"Accessible sensitive file: {path}",
                        full_url,
                        'Medium'
                    )
            except Exception as e:
                self.update_status(f"Sensitive data check error: {str(e)}")

    def check_subdomain_takeover(self):
        if not self.root_domain:
            return
            
        self.update_status("Checking for subdomain takeovers...")
        for sub in self.payloads['common_subdomains']:
            if not self.scanning: return
            try:
                test_sub = f"{sub}.{self.root_domain}"
                
                # DNS check
                try:
                    answers = dns.resolver.resolve(test_sub, 'A')
                except:
                    continue
                
                # HTTP check
                test_url = f"http://{test_sub}"
                res = self.session.get(test_url, timeout=8, allow_redirects=False)
                
                # Common takeover patterns
                if res.status_code in [404, 503] and any(
                    s in res.text.lower() for s in ['aws', 'cloudfront', 'heroku']
                ):
                    self.report_finding(
                        'Subdomain Takeover',
                        f"Vulnerable subdomain detected: {test_sub}",
                        test_url,
                        'High'
                    )
            except Exception as e:
                self.update_status(f"Subdomain check error: {str(e)}")

    def check_access_control(self):
        self.update_status("Checking for broken access control...")
        test_urls = [
            f"{self.target_url}/admin",
            f"{self.target_url}/config",
            f"{self.target_url}/api/users/1"
        ]
        
        for url in test_urls:
            if not self.scanning: return
            try:
                res = self.session.get(url, timeout=8)
                
                # IDOR pattern check
                if "admin" in res.text.lower() and res.status_code == 200:
                    self.report_finding(
                        'Broken Access Control',
                        f"Unauthorized access to privileged endpoint: {url}",
                        url,
                        'High'
                    )
                
                # Horizontal privilege escalation
                if "user_id" in res.text.lower():
                    modified_url = url.replace("user_id=1", "user_id=2")
                    res2 = self.session.get(modified_url, timeout=8)
                    if res2.status_code == 200 and res.text == res2.text:
                        self.report_finding(
                            'Insecure Direct Object Reference (IDOR)',
                            f"Access to other user's data via {modified_url}",
                            modified_url,
                            'High'
                        )
            except Exception as e:
                self.update_status(f"Access control check error: {str(e)}")

    def check_auth_bypass(self):
        self.update_status("Checking for authentication bypass...")
        login_url = urljoin(self.target_url, "/login")
        
        for payload in self.payloads['auth_bypass']:
            if not self.scanning: return
            try:
                res = self.session.post(login_url, data=payload, timeout=10)
                
                if "welcome" in res.text.lower() or "dashboard" in res.text.lower():
                    self.report_finding(
                        'Authentication Bypass',
                        f"Successful login with payload: {payload}",
                        str(payload),
                        'Critical'
                    )
            except Exception as e:
                self.update_status(f"Auth bypass check error: {str(e)}")

    def check_csrf(self):
        self.update_status("Checking for CSRF vulnerabilities...")
        try:
            res = self.session.get(self.target_url, timeout=8)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            for form in soup.find_all('form'):
                if not form.find('input', {'name': ['csrf', 'token', '_token']}):
                    action = form.get('action', self.target_url)
                    self.report_finding(
                        'Cross-Site Request Forgery (CSRF)',
                        f"Form missing CSRF protection: {action}",
                        str(form)[:200] + "...",
                        'Medium'
                    )
        except Exception as e:
            self.update_status(f"CSRF check error: {str(e)}")

    def full_scan(self):
        self.update_status(f"Starting comprehensive scan of {self.target_url}")
        
        # Run all checks in parallel threads
        threads = []
        checks = [
            self.check_xss,
            self.check_sqli,
            self.check_sensitive_data,
            self.check_subdomain_takeover,
            self.check_access_control,
            self.check_auth_bypass,
            self.check_csrf
        ]
        
        for check in checks:
            t = threading.Thread(target=check)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.update_status("Scan completed!")
        return self.vulnerabilities

@app.route('/')
def index():
    return render_template('scanner.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    scanner = AdvancedWebScanner(data['url'], data.get('domain'))
    
    def run_scan():
        try:
            vulnerabilities = scanner.full_scan()
            return jsonify({
                'status': 'completed',
                'findings': vulnerabilities,
                'count': len(vulnerabilities)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    return run_scan()

@socketio.on('start_scan')
def handle_start_scan(data):
    scanner = AdvancedWebScanner(data['url'], data.get('domain'))
    
    def run_scan():
        scanner.full_scan()
        socketio.emit('scan_complete', {
            'findings': scanner.vulnerabilities,
            'count': len(scanner.vulnerabilities)
        })
    
    threading.Thread(target=run_scan).start()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
