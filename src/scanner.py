import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import time
from datetime import datetime
import sys
from pathlib import Path

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
    
    def scan(self):
        self.start_time = time.time()
        print_info(f"Hora de início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
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
            print()
        
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
    
    def get_scan_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print_error("Uso incorreto!")
        print_info("Uso: python scanner.py <URL> [--format FORMAT]")
        print_info("Exemplo: python scanner.py http://testphp.vulnweb.com --format json")
        print_info("Formatos: txt, json, csv, md")
        sys.exit(1)
    
    target = sys.argv[1]
    
    report_format = 'txt'
    if '--format' in sys.argv:
        format_index = sys.argv.index('--format')
        if format_index + 1 < len(sys.argv):
            report_format = sys.argv[format_index + 1]
    
    if not is_valid_http_url(target):
        print_error(f"URL inválida: {target}")
        print_info("A URL deve começar com http:// ou https://")
        sys.exit(1)
    
    scanner = WebScanner(target)
    scanner.scan()
    
    print_info(f"\nGerando relatório em formato {report_format.upper()}...")
    generator = ReportGenerator(
        scanner.vulnerabilities, 
        target,
        scanner.get_scan_duration()
    )
    
    if report_format == 'txt':
        print("\n" + generator.generate_text_report())
    elif report_format == 'json':
        print("\n" + generator.generate_json_report())
    elif report_format == 'csv':
        print("\n" + generator.generate_csv_report())
    elif report_format == 'md':
        print("\n" + generator.generate_markdown_report())
    
    try:
        filepath = generator.save_report(report_format)
        print_success(f"Relatório salvo em: {filepath}")
    except Exception as e:
        print_error(f"Erro ao salvar relatório: {str(e)}")


if __name__ == "__main__":
    main()