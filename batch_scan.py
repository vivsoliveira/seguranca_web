import sys
from pathlib import Path
import json
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from scanner import WebScanner
from utils.helpers import print_banner, print_success, print_error, print_info, is_valid_http_url

class BatchScanner:
    def __init__(self, urls_file):
        self.urls_file = urls_file
        self.results = []
    
    def load_urls(self):
        try:
            with open(self.urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return urls
        except FileNotFoundError:
            print_error(f"Arquivo não encontrado: {self.urls_file}")
            return []
    
    def scan_all(self):
        urls = self.load_urls()
        
        if not urls:
            print_error("Nenhuma URL para varrer")
            return
        
        print_info(f"Total de URLs a varrer: {len(urls)}\n")
        
        for i, url in enumerate(urls, 1):
            print_info(f"[{i}/{len(urls)}] Varrendo: {url}")
            
            if not is_valid_http_url(url):
                print_error(f"URL inválida, pulando: {url}\n")
                continue
            
            scanner = WebScanner(url)
            scanner.scan()
            
            result = {
                "url": url,
                "scan_time": datetime.now().isoformat(),
                "vulnerabilities": scanner.vulnerabilities,
                "vuln_count": len(scanner.vulnerabilities),
                "duration": scanner.get_scan_duration()
            }
            self.results.append(result)
            
            print_success(f"Varredura concluída: {len(scanner.vulnerabilities)} vulnerabilidades\n")
        
        self.generate_summary()
    
    def generate_summary(self):
        print_info("\n" + "="*60)
        print_info("RESUMO GERAL DA VARREDURA")
        print_info("="*60 + "\n")
        
        total_urls = len(self.results)
        total_vulns = sum(r["vuln_count"] for r in self.results)
        
        print_info(f"URLs varridas: {total_urls}")
        print_info(f"Total de vulnerabilidades: {total_vulns}")
        
        print_info("\nPor URL:")
        for result in self.results:
            status = "🔴" if result["vuln_count"] > 0 else "🟢"
            print_info(f"{status} {result['url']}: {result['vuln_count']} vulnerabilidades")
        
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        filename = f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = reports_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print_success(f"\nRelatório consolidado salvo: {filepath}")


def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print_error("Uso incorreto!")
        print_info("Uso: python batch_scan.py <arquivo_urls.txt>")
        print_info("Exemplo: python batch_scan.py urls.txt")
        sys.exit(1)
    
    urls_file = sys.argv[1]
    batch = BatchScanner(urls_file)
    batch.scan_all()


if __name__ == "__main__":
    main()