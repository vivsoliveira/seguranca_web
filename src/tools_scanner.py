import subprocess
import json
import re
from urllib.parse import urlparse
from pathlib import Path

class ToolsScanner:
    """Integração com ferramentas de segurança externas"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.host = self._extract_host()
        self.vulnerabilities = []
    
    def _extract_host(self):
        """Extrai host e porta da URL"""
        parsed = urlparse(self.target_url)
        return parsed.netloc
    
    def check_tools_installed(self):
        """Verifica quais ferramentas estão instaladas"""
        tools = {
            'nmap': self._check_command('nmap'),
            'nikto': self._check_command('nikto'),
        }
        return tools
    
    def _check_command(self, command):
        """Verifica se comando está disponível"""
        try:
            subprocess.run([command, '--version'], 
                         capture_output=True, 
                         timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_with_nmap(self):
        """Escaneia portas e serviços com Nmap"""
        print("[*] Executando Nmap...")
        
        try:
            result = subprocess.run(
                ['nmap', '-sV', '-sC', '--script=vuln', self.host, '-oX', '-'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self._parse_nmap_output(result.stdout)
                return True
            else:
                print(f"[!] Nmap falhou: {result.stderr}")
                return False
                
        except FileNotFoundError:
            print("[!] Nmap não instalado")
            return False
        except subprocess.TimeoutExpired:
            print("[!] Nmap timeout")
            return False
    
    def _parse_nmap_output(self, output):
        """Parseia saída XML do Nmap"""
        if 'VULNERABLE' in output or 'CVE-' in output:
            cve_pattern = r'CVE-\d{4}-\d+'
            cves = re.findall(cve_pattern, output)
            
            if cves:
                vuln = {
                    "type": "Known Vulnerabilities (Nmap)",
                    "severity": "ALTA",
                    "url": self.target_url,
                    "method": "NMAP",
                    "parameter": f"CVEs encontradas: {', '.join(set(cves))}",
                    "payload": "N/A",
                    "tool": "nmap"
                }
                self.vulnerabilities.append(vuln)
        
        if '<port protocol="tcp" portid="' in output:
            open_ports = re.findall(r'portid="(\d+)".*?state="open"', output)
            if len(open_ports) > 10:
                vuln = {
                    "type": "Too Many Open Ports",
                    "severity": "MÉDIA",
                    "url": self.target_url,
                    "method": "NMAP",
                    "parameter": f"{len(open_ports)} portas abertas",
                    "payload": "N/A",
                    "details": f"Portas: {', '.join(open_ports[:10])}...",
                    "tool": "nmap"
                }
                self.vulnerabilities.append(vuln)
    
    def scan_with_nikto(self):
        """Escaneia vulnerabilidades web com Nikto"""
        print("[*] Executando Nikto...")
        
        try:
            result = subprocess.run(
                ['nikto', '-h', self.target_url, '-Format', 'json', '-output', '-'],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0 or result.stdout:
                self._parse_nikto_output(result.stdout)
                return True
            else:
                print(f"[!] Nikto falhou: {result.stderr}")
                return False
                
        except FileNotFoundError:
            print("[!] Nikto não instalado")
            return False
        except subprocess.TimeoutExpired:
            print("[!] Nikto timeout")
            return False
    
    def _parse_nikto_output(self, output):
        """Parseia saída JSON do Nikto"""
        try:
            data = json.loads(output)
            
            if 'vulnerabilities' in data:
                for vuln_data in data['vulnerabilities']:
                    severity = self._map_nikto_severity(vuln_data.get('OSVDB', ''))
                    
                    vuln = {
                        "type": f"Nikto: {vuln_data.get('msg', 'Unknown')}",
                        "severity": severity,
                        "url": vuln_data.get('url', self.target_url),
                        "method": vuln_data.get('method', 'GET'),
                        "parameter": vuln_data.get('uri', 'N/A'),
                        "payload": "N/A",
                        "tool": "nikto"
                    }
                    self.vulnerabilities.append(vuln)
                    
        except json.JSONDecodeError:
            lines = output.split('\n')
            for line in lines:
                if '+ OSVDB-' in line or 'WARNING:' in line:
                    vuln = {
                        "type": "Nikto Finding",
                        "severity": "MÉDIA",
                        "url": self.target_url,
                        "method": "NIKTO",
                        "parameter": line.strip()[:100],
                        "payload": "N/A",
                        "tool": "nikto"
                    }
                    self.vulnerabilities.append(vuln)
    
    def _map_nikto_severity(self, osvdb):
        """Mapeia OSVDB para severidade"""
        if not osvdb:
            return "MÉDIA"
        return "ALTA"
    
    
    def run_all_scans(self):
        """Executa todas as ferramentas disponíveis"""
        tools = self.check_tools_installed()
        
        print(f"\n[*] Ferramentas disponíveis:")
        for tool, installed in tools.items():
            status = "✓" if installed else "✗"
            print(f"    {status} {tool}")
        
        if not any(tools.values()):
            print("\n[!] Nenhuma ferramenta auxiliar instalada!")
            print("[i] Para instalar:")
            print("    sudo apt install nmap nikto")
            return False
        
        print(f"\n[*] Iniciando varredura com ferramentas externas...")
        
        if tools['nmap']:
            self.scan_with_nmap()
        
        if tools['nikto']:
            self.scan_with_nikto()
        
        print(f"\n[+] Ferramentas encontraram {len(self.vulnerabilities)} vulnerabilidades adicionais")
        return True


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python tools_scanner.py <URL>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = ToolsScanner(target)
    scanner.run_all_scans()
    
    print(f"\n[*] Vulnerabilidades encontradas:")
    for vuln in scanner.vulnerabilities:
        print(f"  - {vuln['type']} ({vuln['severity']})")