import json
import csv
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Classe responsável por gerar relatórios em diferentes formatos"""
    
    def __init__(self, vulnerabilities, target_url, scan_duration=None):
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url
        self.scan_duration = scan_duration
        self.timestamp = datetime.now()
    
    def generate_text_report(self):
        """Gera relatório em formato texto"""
        report = []
        report.append("=" * 80)
        report.append("RELATÓRIO DE VARREDURA DE SEGURANÇA")
        report.append("=" * 80)
        report.append(f"\nURL Alvo: {self.target_url}")
        report.append(f"Data/Hora: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.scan_duration:
            report.append(f"Duração: {self.scan_duration:.2f} segundos")
        report.append(f"Total de Vulnerabilidades: {len(self.vulnerabilities)}\n")
        report.append("=" * 80)
        
        if not self.vulnerabilities:
            report.append("\n✓ Nenhuma vulnerabilidade detectada nos testes básicos.")
        else:
            report.append("\n[!] VULNERABILIDADES DETECTADAS:\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"\n--- Vulnerabilidade #{i} ---")
                report.append(f"Tipo: {vuln['type']}")
                report.append(f"Severidade: {vuln['severity']}")
                report.append(f"URL: {vuln['url']}")
                report.append(f"Método: {vuln['method']}")
                report.append(f"Parâmetro: {vuln['parameter']}")
                report.append(f"Payload: {vuln['payload']}")
                if 'error' in vuln:
                    report.append(f"Erro: {vuln['error']}")
        
        report.append("\n" + "=" * 80)
        report.append("RESUMO DOS TESTES")
        report.append("=" * 80)
        report.append(f"✓ Teste de XSS realizado")
        report.append(f"✓ Teste de SQL Injection realizado")
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)
    
    def generate_json_report(self):
        """Gera relatório em formato JSON"""
        report = {
            "scan_info": {
                "target_url": self.target_url,
                "timestamp": self.timestamp.isoformat(),
                "scan_duration": self.scan_duration,
                "total_vulnerabilities": len(self.vulnerabilities)
            },
            "vulnerabilities": self.vulnerabilities,
            "summary": {
                "tests_performed": ["XSS", "SQL Injection"],
                "severity_count": self._count_by_severity()
            }
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def generate_csv_report(self):
        """Gera relatório em formato CSV"""
        if not self.vulnerabilities:
            return "Nenhuma vulnerabilidade encontrada"
        
        output = []
        headers = ["Tipo", "Severidade", "URL", "Método", "Parâmetro", "Payload"]
        output.append(",".join(headers))
        
        for vuln in self.vulnerabilities:
            row = [
                vuln.get('type', ''),
                vuln.get('severity', ''),
                vuln.get('url', ''),
                vuln.get('method', ''),
                vuln.get('parameter', ''),
                f"\"{vuln.get('payload', '')}\""  # Aspas para payloads com vírgulas
            ]
            output.append(",".join(row))
        
        return "\n".join(output)
    
    def generate_markdown_report(self):
        """Gera relatório em formato Markdown"""
        report = []
        report.append(f"# Relatório de Varredura de Segurança\n")
        report.append(f"**URL Alvo:** {self.target_url}  ")
        report.append(f"**Data/Hora:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  ")
        if self.scan_duration:
            report.append(f"**Duração:** {self.scan_duration:.2f}s  ")
        report.append(f"**Total de Vulnerabilidades:** {len(self.vulnerabilities)}\n")
        
        if not self.vulnerabilities:
            report.append("✅ **Nenhuma vulnerabilidade detectada**\n")
        else:
            report.append("## 🔴 Vulnerabilidades Detectadas\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"### {i}. {vuln['type']}\n")
                report.append(f"- **Severidade:** {vuln['severity']}")
                report.append(f"- **URL:** `{vuln['url']}`")
                report.append(f"- **Método:** {vuln['method']}")
                report.append(f"- **Parâmetro:** `{vuln['parameter']}`")
                report.append(f"- **Payload:** `{vuln['payload']}`")
                if 'error' in vuln:
                    report.append(f"- **Erro:** {vuln['error']}")
                report.append("")
        
        report.append("## 📊 Resumo\n")
        severity_count = self._count_by_severity()
        for severity, count in severity_count.items():
            report.append(f"- **{severity}:** {count}")
        
        return "\n".join(report)
    
    def _count_by_severity(self):
        """Conta vulnerabilidades por severidade"""
        count = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'DESCONHECIDA')
            count[severity] = count.get(severity, 0) + 1
        return count
    
    def save_report(self, format='txt', output_dir='reports'):
        """Salva relatório no formato especificado"""
        Path(output_dir).mkdir(exist_ok=True)
        
        timestamp_str = self.timestamp.strftime('%Y%m%d_%H%M%S')
        
        if format == 'txt':
            content = self.generate_text_report()
            filename = f"report_{timestamp_str}.txt"
        elif format == 'json':
            content = self.generate_json_report()
            filename = f"report_{timestamp_str}.json"
        elif format == 'csv':
            content = self.generate_csv_report()
            filename = f"report_{timestamp_str}.csv"
        elif format == 'md':
            content = self.generate_markdown_report()
            filename = f"report_{timestamp_str}.md"
        else:
            raise ValueError(f"Formato não suportado: {format}")
        
        filepath = Path(output_dir) / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(filepath)


if __name__ == "__main__":
    # Exemplo de uso
    test_vulnerabilities = [
        {
            "type": "XSS (Cross-Site Scripting)",
            "severity": "MÉDIA",
            "url": "http://example.com/search",
            "method": "GET",
            "parameter": "q",
            "payload": "<script>alert('XSS')</script>"
        },
        {
            "type": "SQL Injection",
            "severity": "ALTA",
            "url": "http://example.com/login",
            "method": "POST",
            "parameter": "username",
            "payload": "' OR '1'='1",
            "error": "sql syntax error"
        }
    ]
    
    generator = ReportGenerator(test_vulnerabilities, "http://example.com")
    
    print("Gerando relatórios de exemplo...")
    generator.save_report('txt')
    generator.save_report('json')
    generator.save_report('csv')
    generator.save_report('md')
    print("Relatórios salvos na pasta 'reports/'")