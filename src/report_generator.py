import json
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Classe responsável por gerar relatórios em formato JSON"""
    
    def __init__(self, vulnerabilities, target_url, scan_duration=None):
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url
        self.scan_duration = scan_duration
        self.timestamp = datetime.now()
    
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
                "tests_performed": [
                    "XSS",
                    "SQL Injection",
                    "CSRF",
                    "Path Traversal",
                    "File Inclusion",
                    "Sensitive Data Exposure",
                    "Insecure Headers"
                ],
                "severity_count": self._count_by_severity()
            }
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _count_by_severity(self):
        """Conta vulnerabilidades por severidade"""
        count = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'DESCONHECIDA')
            count[severity] = count.get(severity, 0) + 1
        return count
    
    def save_report(self, filepath):
        """Salva relatório JSON no caminho especificado"""
        content = self.generate_json_report()
        
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return filepath


if __name__ == "__main__":
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
    
    generator = ReportGenerator(test_vulnerabilities, "http://example.com", 10.5)
        
    filepath = generator.save_report("reports/example1.json")
    print(f"\nRelatório salvo em: {filepath}")