import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
from datetime import datetime
import sys
from pathlib import Path
import re
import os

sys.path.insert(0, str(Path(__file__).parent))
from report_generator import ReportGenerator
from utils.helpers import (
    print_banner, print_success, print_error, print_info, 
    is_valid_http_url, format_vulnerability_output
)

class WebScanner:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []
        self.tested_urls = set()
        self.start_time = None
        self.end_time = None
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' UNION SELECT NULL--"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/backdoor.php"
        ]
    
    def scan(self):
        self.start_time = time.time()
        print_info(f"Hora de início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        self.check_security_headers()
        
        forms = self.get_forms()
        if not forms:
            print_info("Nenhum formulário encontrado na página")
            self.end_time = time.time()
            return
        
        print_success(f"{len(forms)} formulário(s) encontrado(s)\n")
        
        for i, form in enumerate(forms, 1):
            print_info(f"Testando formulário {i}/{len(forms)}")
            self.test_xss(form)
            self.test_sql_injection(form)
            self.test_csrf(form)
            self.test_path_traversal(form)
            self.test_file_inclusion(form)
            print()
        
        self.test_sensitive_data_exposure()
        
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        
        print_success("Varredura concluída!")
        print_info(f"Duração: {duration:.2f} segundos")
        print_info(f"Qtde de vulnerabilidades: {len(self.vulnerabilities)}")
    
    def get_forms(self):
        try:
            response = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print_error(f"Erro ao acessar {self.url}: {str(e)}")
            return []
    
    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def test_xss(self, form):
        details = self.get_form_details(form)
        
        for payload in self.xss_payloads:
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ["text", "search", "email"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            url = urljoin(self.url, details["action"])
            
            try:
                if details["method"] == "post":
                    response = requests.post(url, data=data, timeout=5)
                else:
                    response = requests.get(url, params=data, timeout=5)
                
                if payload in response.text:
                    vuln = {
                        "type": "XSS (Cross-Site Scripting)",
                        "severity": "MÉDIA",
                        "url": url,
                        "method": details["method"].upper(),
                        "payload": payload,
                        "parameter": list(data.keys())[0] if data else "N/A"
                    }
                    self.vulnerabilities.append(vuln)
                    print(format_vulnerability_output(vuln))
                    break
                    
            except Exception:
                continue
            
            time.sleep(0.5)
    
    def test_csrf(self, form):
        details = self.get_form_details(form)
        
        csrf_tokens = ['csrf', 'token', '_token', 'csrf_token', 'authenticity_token']
        has_csrf_protection = False
        
        for input_field in details["inputs"]:
            input_name = input_field["name"].lower()
            if any(token in input_name for token in csrf_tokens):
                has_csrf_protection = True
                break
        
        if not has_csrf_protection and details["method"] == "post":
            url = urljoin(self.url, details["action"])
            vuln = {
                "type": "CSRF (Cross-Site Request Forgery)",
                "severity": "MÉDIA",
                "url": url,
                "method": details["method"].upper(),
                "payload": "N/A",
                "parameter": "Formulário sem token CSRF"
            }
            self.vulnerabilities.append(vuln)
            print(format_vulnerability_output(vuln))
    
    def test_path_traversal(self, form):
        details = self.get_form_details(form)
        
        for payload in self.path_traversal_payloads:
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ["text", "search", "file"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            url = urljoin(self.url, details["action"])
            
            try:
                if details["method"] == "post":
                    response = requests.post(url, data=data, timeout=5)
                else:
                    response = requests.get(url, params=data, timeout=5)
                
                traversal_indicators = [
                    "root:x:",
                    "[extensions]",
                    "bin/bash",
                    "windows",
                    "system32"
                ]
                
                response_lower = response.text.lower()
                for indicator in traversal_indicators:
                    if indicator in response_lower:
                        vuln = {
                            "type": "Path Traversal",
                            "severity": "ALTA",
                            "url": url,
                            "method": details["method"].upper(),
                            "payload": payload,
                            "parameter": list(data.keys())[0] if data else "N/A"
                        }
                        self.vulnerabilities.append(vuln)
                        print(format_vulnerability_output(vuln))
                        return
                        
            except Exception:
                continue
            
            time.sleep(0.5)
    
    def test_sql_injection(self, form):
        details = self.get_form_details(form)
        
        for payload in self.sqli_payloads:
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ["text", "search", "email", "password"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            url = urljoin(self.url, details["action"])
            
            try:
                if details["method"] == "post":
                    response = requests.post(url, data=data, timeout=5)
                else:
                    response = requests.get(url, params=data, timeout=5)
                
                sql_errors = [
                    "sql syntax",
                    "mysql_fetch",
                    "you have an error in your sql",
                    "warning: mysql",
                    "unclosed quotation mark",
                    "quoted string not properly terminated"
                ]
                
                response_lower = response.text.lower()
                for error in sql_errors:
                    if error in response_lower:
                        vuln = {
                            "type": "SQL Injection",
                            "severity": "ALTA",
                            "url": url,
                            "method": details["method"].upper(),
                            "payload": payload,
                            "parameter": list(data.keys())[0] if data else "N/A",
                            "error": error
                        }
                        self.vulnerabilities.append(vuln)
                        print(format_vulnerability_output(vuln))
                        return
                        
            except Exception:
                continue
            
            time.sleep(0.5)
    
    def test_file_inclusion(self, form):
        details = self.get_form_details(form)
        
        for payload in self.lfi_payloads:
            data = {}
            for input_field in details["inputs"]:
                if input_field["type"] in ["text", "search", "file"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            url = urljoin(self.url, details["action"])
            
            try:
                if details["method"] == "post":
                    response = requests.post(url, data=data, timeout=5)
                else:
                    response = requests.get(url, params=data, timeout=5)
                
                lfi_indicators = [
                    "root:x:",
                    "daemon:",
                    "[extensions]",
                    "bin/bash",
                    "# localhost",
                    "<?php"
                ]
                
                response_lower = response.text.lower()
                for indicator in lfi_indicators:
                    if indicator.lower() in response_lower:
                        vuln = {
                            "type": "Local File Inclusion (LFI)",
                            "severity": "ALTA",
                            "url": url,
                            "method": details["method"].upper(),
                            "payload": payload,
                            "parameter": list(data.keys())[0] if data else "N/A"
                        }
                        self.vulnerabilities.append(vuln)
                        print(format_vulnerability_output(vuln))
                        return
                        
            except Exception:
                continue
            
            time.sleep(0.5)
    
    def test_sensitive_data_exposure(self):
        try:
            common_files = [
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/database.yml',
                '/.git/config',
                '/backup.sql',
                '/phpinfo.php',
                '/admin',
                '/robots.txt',
                '/.DS_Store'
            ]
            
            for file_path in common_files:
                test_url = urljoin(self.url, file_path)
                
                try:
                    response = requests.get(test_url, timeout=3)
                    
                    if response.status_code == 200:
                        sensitive_patterns = [
                            'password',
                            'api_key',
                            'secret',
                            'db_password',
                            'mysql',
                            'postgres',
                            'mongodb',
                            'aws_access',
                            'private_key'
                        ]
                        
                        content_lower = response.text.lower()
                        found_patterns = [p for p in sensitive_patterns if p in content_lower]
                        
                        if found_patterns or len(response.text) > 100:
                            vuln = {
                                "type": "Sensitive Data Exposure",
                                "severity": "ALTA" if found_patterns else "MÉDIA",
                                "url": test_url,
                                "method": "GET",
                                "payload": "N/A",
                                "parameter": f"Arquivo exposto: {file_path}"
                            }
                            
                            if found_patterns:
                                vuln["details"] = f"Padrões sensíveis encontrados: {', '.join(found_patterns)}"
                            
                            self.vulnerabilities.append(vuln)
                            print(format_vulnerability_output(vuln))
                
                except Exception:
                    continue
                
                time.sleep(0.3)
                
        except Exception:
            pass
    
    def check_security_headers(self):
        try:
            response = requests.get(self.url, timeout=5)
            headers = response.headers
            
            required_headers = {
                'X-Frame-Options': 'Proteção contra Clickjacking',
                'X-Content-Type-Options': 'Proteção contra MIME sniffing',
                'Strict-Transport-Security': 'Força uso de HTTPS',
                'Content-Security-Policy': 'Proteção contra XSS',
                'X-XSS-Protection': 'Filtro XSS do navegador'
            }
            
            missing_headers = []
            for header, description in required_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                vuln = {
                    "type": "Insecure Headers",
                    "severity": "BAIXA",
                    "url": self.url,
                    "method": "GET",
                    "payload": "N/A",
                    "parameter": ", ".join(missing_headers)
                }
                self.vulnerabilities.append(vuln)
                print(format_vulnerability_output(vuln))
                
        except Exception:
            pass
    
    def get_scan_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


def get_incremental_filename(url, format='json'):
    """Gera nome de arquivo incremental baseado na URL"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '').replace('.', '_').replace(':', '_')
    
    domain = re.sub(r'[^a-zA-Z0-9_]', '', domain)
    
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    
    counter = 1
    while True:
        filename = f"{domain}{counter}.{format}"
        filepath = reports_dir / filename
        if not filepath.exists():
            return str(filepath)
        counter += 1


def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print_error("Uso incorreto!")
        print_info("Uso: python scanner.py <URL>")
        print_info("Exemplo: python scanner.py http://testphp.vulnweb.com")
        sys.exit(1)
    
    target = sys.argv[1]
    report_format = 'json'  # Formato padrão JSON
    
    if not is_valid_http_url(target):
        print_error(f"URL inválida: {target}")
        print_info("A URL deve começar com http:// ou https://")
        sys.exit(1)
    
    scanner = WebScanner(target)
    scanner.scan()
    
    generator = ReportGenerator(
        scanner.vulnerabilities, 
        target,
        scanner.get_scan_duration()
    )
    
    try:
        filepath = get_incremental_filename(target, report_format)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(generator.generate_json_report())
        
        print_success(f"Relatório salvo em: {filepath}")
    except Exception as e:
        print_error(f"Erro ao salvar relatório: {str(e)}")


if __name__ == "__main__":
    main()