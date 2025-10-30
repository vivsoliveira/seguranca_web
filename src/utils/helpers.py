from urllib.parse import urlparse, urljoin
import re
import sys

class Colors:
    """Cores para output no terminal"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Exibe banner da ferramenta"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║          Web Security Scanner - Conceito C            ║
    ║              Ferramenta de Testes de Segurança        ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(Colors.OKCYAN + banner + Colors.ENDC)

def validate_url(url):
    """Valida se a URL é válida"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_http_url(url):
    """Verifica se é uma URL HTTP/HTTPS válida"""
    if not validate_url(url):
        return False
    
    parsed = urlparse(url)
    return parsed.scheme in ['http', 'https']

def clean_url(url):
    """Remove parâmetros e fragmentos da URL"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def extract_domain(url):
    """Extrai o domínio da URL"""
    parsed = urlparse(url)
    return parsed.netloc

def is_same_domain(url1, url2):
    """Verifica se duas URLs pertencem ao mesmo domínio"""
    return extract_domain(url1) == extract_domain(url2)

def print_success(message):
    """Imprime mensagem de sucesso"""
    print(f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}")

def print_error(message):
    """Imprime mensagem de erro"""
    print(f"{Colors.FAIL}[!] {message}{Colors.ENDC}", file=sys.stderr)

def print_info(message):
    """Imprime mensagem informativa"""
    print(f"{Colors.OKBLUE}[*] {message}{Colors.ENDC}")

def print_warning(message):
    """Imprime mensagem de aviso"""
    print(f"{Colors.WARNING}[⚠] {message}{Colors.ENDC}")

def sanitize_filename(filename):
    """Remove caracteres inválidos de nome de arquivo"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def get_severity_color(severity):
    """Retorna cor baseada na severidade"""
    severity_upper = severity.upper()
    if severity_upper == 'ALTA' or severity_upper == 'HIGH':
        return Colors.FAIL
    elif severity_upper == 'MÉDIA' or severity_upper == 'MEDIUM':
        return Colors.WARNING
    else:
        return Colors.OKBLUE

def format_vulnerability_output(vuln):
    """Formata vulnerabilidade para exibição colorida"""
    color = get_severity_color(vuln.get('severity', 'BAIXA'))
    output = f"""
{color}╔═══════════════════════════════════════════════════════╗
║ VULNERABILIDADE DETECTADA
╚═══════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.BOLD}Tipo:{Colors.ENDC} {vuln.get('type', 'N/A')}
{Colors.BOLD}Severidade:{Colors.ENDC} {color}{vuln.get('severity', 'N/A')}{Colors.ENDC}
{Colors.BOLD}URL:{Colors.ENDC} {vuln.get('url', 'N/A')}
{Colors.BOLD}Método:{Colors.ENDC} {vuln.get('method', 'N/A')}
{Colors.BOLD}Parâmetro:{Colors.ENDC} {vuln.get('parameter', 'N/A')}
{Colors.BOLD}Payload:{Colors.ENDC} {vuln.get('payload', 'N/A')}
"""
    if 'error' in vuln:
        output += f"{Colors.BOLD}Erro:{Colors.ENDC} {vuln.get('error', 'N/A')}\n"
    
    return output

def get_user_agent():
    """Retorna User-Agent padrão para requisições"""
    return "WebSecurityScanner/1.0 (Educational Purpose)"

def truncate_string(text, max_length=100):
    """Trunca string se for muito longa"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."