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
        """Escaneia portas e serviços com Nmap (versão otimizada)"""
        print("[*] Executando Nmap (scan rápido)...")
        
        try:
            # Scan otimizado: apenas top 100 portas, sem scripts pesados
            result = subprocess.run(
                ['nmap', '-F', '-sV', '--version-intensity', '2', self.host],
                capture_output=True,
                text=True,
                timeout=120  # 2 minutos max
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
            print("[!] Nmap timeout (mais de 2 minutos)")
            return False
    
    def _parse_nmap_output(self, output):
        """Parseia saída texto do Nmap"""
        lines = output.split('\n')
        open_ports = []
        
        # Procura por portas abertas
        for line in lines:
            if '/tcp' in line and 'open' in line:
                match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if match:
                    port = match.group(1)
                    service = match.group(2)
                    open_ports.append(f"{port}/{service}")
        
        if open_ports:
            # Registra portas abertas como vulnerabilidade de informação
            severity = "MÉDIA" if len(open_ports) > 10 else "BAIXA"
            vuln = {
                "type": "Exposed Services (Nmap)",
                "severity": severity,
                "url": self.target_url,
                "method": "NMAP",
                "parameter": f"{len(open_ports)} portas abertas",
                "payload": "N/A",
                "details": f"Serviços: {', '.join(open_ports[:10])}",
                "tool": "nmap"
            }
            self.vulnerabilities.append(vuln)
        
        # Procura por versões específicas conhecidas como vulneráveis
        vulnerable_versions = {
            'Apache/2.2': 'Apache 2.2 (fim de suporte)',
            'Apache/2.0': 'Apache 2.0 (fim de suporte)',
            'nginx/1.0': 'Nginx 1.0 (desatualizado)',
            'OpenSSH 5': 'OpenSSH 5.x (vulnerável)',
            'OpenSSH 6': 'OpenSSH 6.x (vulnerável)',
        }
        
        for pattern, description in vulnerable_versions.items():
            if pattern in output:
                vuln = {
                    "type": "Outdated Service Version (Nmap)",
                    "severity": "ALTA",
                    "url": self.target_url,
                    "method": "NMAP",
                    "parameter": description,
                    "payload": "N/A",
                    "tool": "nmap"
                }
                self.vulnerabilities.append(vuln)
                break
    
    def scan_with_nikto(self):
        """Escaneia vulnerabilidades web com Nikto (versão otimizada)"""
        print("[*] Executando Nikto (scan básico)...")
        
        try:
            # Scan otimizado: apenas testes básicos e rápidos
            result = subprocess.run(
                ['nikto', '-h', self.target_url, '-Tuning', '1234', '-timeout', '10'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos max
            )
            
            # Nikto pode retornar código de erro mas ter output válido
            if result.stdout:
                self._parse_nikto_output(result.stdout)
                return True
            else:
                print(f"[!] Nikto não retornou resultados")
                return False
                
        except FileNotFoundError:
            print("[!] Nikto não instalado")
            return False
        except subprocess.TimeoutExpired:
            print("[!] Nikto timeout (mais de 5 minutos)")
            return False
    
    def _parse_nikto_output(self, output):
        """Parseia saída texto do Nikto"""
        lines = output.split('\n')
        findings = []
        
        for line in lines:
            line = line.strip()
            
            # Pula linhas vazias e cabeçalhos
            if not line or line.startswith('-') or line.startswith('='):
                continue
            
            # Procura por linhas que começam com '+'
            if line.startswith('+ '):
                finding = line[2:].strip()  # Remove o '+ '
                
                # Filtra linhas informativas irrelevantes
                skip_patterns = [
                    'Target IP:',
                    'Target Hostname:',
                    'Target Port:',
                    'Start Time:',
                    'Server:',
                    'retrieved x-powered-by header',
                    'No CGI Directories found',
                ]
                
                should_skip = False
                for pattern in skip_patterns:
                    if pattern.lower() in finding.lower():
                        should_skip = True
                        break
                
                if not should_skip and len(finding) > 20:  # Apenas achados com conteúdo
                    findings.append(finding)
        
        # Registra achados como vulnerabilidades
        for finding in findings:
            # Determina severidade baseada em palavras-chave
            severity = "MÉDIA"
            if any(word in finding.lower() for word in ['vulnerable', 'exploit', 'critical', 'high', 'injection']):
                severity = "ALTA"
            elif any(word in finding.lower() for word in ['information', 'disclosure', 'version', 'banner']):
                severity = "BAIXA"
            
            vuln = {
                "type": "Nikto Finding",
                "severity": severity,
                "url": self.target_url,
                "method": "NIKTO",
                "parameter": finding[:150],  # Limita tamanho
                "payload": "N/A",
                "tool": "nikto"
            }
            self.vulnerabilities.append(vuln)
    
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
        print("[i] Isso pode levar alguns minutos...\n")
        
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
        if 'details' in vuln:
            print(f"    Detalhes: {vuln['details']}")