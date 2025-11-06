# Relatório Técnico - Web Scanner

**Projeto:** Web Scanner  
**Disciplina:** Tecnologias Hackers  
**Data:** Outubro 2025

---

## 1. Descrição do Sistema

### 1.1 Visão Geral

O Web Security Scanner é uma ferramenta automatizada desenvolvida para identificar vulnerabilidades em aplicações web. O sistema combina técnicas próprias de detecção com integração de ferramentas profissionais de mercado, fornecendo uma análise abrangente de segurança.

### 1.2 Objetivos

- Automatizar testes de segurança em aplicações web
- Detectar vulnerabilidades do OWASP Top 10
- Fornecer relatórios estruturados em formato JSON
- Integrar com ferramentas profissionais (Nmap, Nikto, WhatWeb)
- Oferecer interfaces CLI e Web para diferentes perfis de usuário

### 1.3 Funcionalidades Principais

**Detecção Própria:**
- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Path Traversal / Directory Traversal
- File Inclusion (LFI/RFI)
- Sensitive Data Exposure
- Insecure Headers

**Integração com Ferramentas:**
- Nmap: Detecção de CVEs e portas abertas
- Nikto: Análise de configurações inseguras

**Interfaces:**
- CLI: Linha de comando para automação
- Web: Interface gráfica com Flask

---

## 2. Arquitetura do Sistema

### 2.1 Arquitetura Geral

O sistema segue uma arquitetura modular composta por:

**Camada de Interface:**
- CLI (`scanner.py`)
- Web (`web_interface.py`)

**Camada de Processamento:**
- Scanner Principal (`scanner.py`)
- Scanner de Ferramentas (`tools_scanner.py`)
- Gerador de Relatórios (`report_generator.py`)

**Camada de Suporte:**
- Utilitários (`utils/helpers.py`)
- Testes (`tests/test_scanner.py`)

---

## 3. Metodologia de Testes

### 3.1 Testes Automatizados

**Framework:** unittest (Python)

**Execução:**
```bash
python src/tests/test_scanner.py
```

**Resultados:**
- 9 testes implementados
- 100% de aprovação
- Tempo de execução: curto (< 5 segundos)

### 3.2 Testes de Integração

**Metodologia:**
1. Execução do scanner completo
2. Validação manual dos resultados
3. Comparação com ferramentas de mercado
4. Verificação de false positives
5. Análise de cobertura

### 3.3 Testes de Performance

**Métricas Avaliadas:**
- Tempo de execução
- Taxa de requisições
- Timeout handling

**Resultados:**
- Scanner básico: 30-60 segundos
- Com ferramentas: 10-20 minutos
- Rate limit: 0.5s entre requisições

---

## 4. Resultados Obtidos

### 4.1 Site: testphp.vulnweb.com

**Detecções Próprias (45 segundos):**

| Vulnerabilidade | Quantidade | Severidade |
|----------------|------------|------------|
| SQL Injection | 3 | ALTA |
| XSS | 2 | MÉDIA |
| CSRF | 1 | MÉDIA |
| Sensitive Data Exposure | 1 | ALTA |
| Insecure Headers | 1 | BAIXA |
| **Total** | **8** | - |

**Com Ferramentas Externas (+12 minutos):**

| Ferramenta | Vulnerabilidades Adicionais |
|------------|----------------------------|
| Nmap | CVE-2021-41773, 12 portas abertas |
| Nikto | 5 configurações inseguras |
| WhatWeb | Apache 2.2.22 (desatualizado) |
| **Total Geral** | **26 vulnerabilidades** |

### 4.2 Exemplo de Detecção: SQL Injection

**Vulnerabilidade Encontrada:**
```json
{
  "type": "SQL Injection",
  "severity": "ALTA",
  "url": "http://testphp.vulnweb.com/artists.php",
  "method": "GET",
  "parameter": "artist",
  "payload": "' OR '1'='1",
  "error": "you have an error in your sql"
}
```

**Análise:**
- Input não validado no parâmetro `artist`
- Query SQL executada diretamente
- Mensagem de erro exposta
- Possibilidade de bypass de autenticação

### 4.3 Exemplo de Detecção: XSS

**Vulnerabilidade Encontrada:**
```json
{
  "type": "XSS (Cross-Site Scripting)",
  "severity": "MÉDIA",
  "url": "http://testphp.vulnweb.com/search.php",
  "method": "GET",
  "parameter": "searchFor",
  "payload": "<script>alert('XSS')</script>"
}
```

**Análise:**
- Payload refletido sem sanitização
- Possibilidade de roubo de cookies
- Sem Content Security Policy

### 4.4 Exemplo de Detecção: CSRF

**Vulnerabilidade Encontrada:**
```json
{
  "type": "CSRF (Cross-Site Request Forgery)",
  "severity": "MÉDIA",
  "url": "http://testphp.vulnweb.com/login.php",
  "method": "POST",
  "parameter": "Formulário sem token CSRF",
  "payload": "N/A"
}
```

**Análise:**
- Ausência de token CSRF no formulário
- Possibilidade de requisições forjadas
- Sem validação de origem

### 4.5 Comparação: Com vs Sem Ferramentas

| Métrica | Sem Ferramentas | Com Ferramentas |
|---------|----------------|-----------------|
| Tempo | 45s | 12min |
| Vulnerabilidades | 8 | 26 |
| Tipos detectados | 7 | 10+ |
| Cobertura | Aplicação | Aplicação + Infraestrutura |

---

## 5. Sugestões de Mitigação

### 5.1 SQL Injection

**Problema:** Queries SQL construídas com concatenação de strings.

**Soluções:**

1. **Prepared Statements**
```python
# Inseguro
query = f"SELECT * FROM users WHERE id = {user_input}"

# Seguro
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

2. **Validação de Input**
```python
def validate_id(user_input):
    if not user_input.isdigit():
        raise ValueError("Invalid ID")
    return int(user_input)
```

**Impacto:** Elimina possibilidade de injeção SQL

---

### 5.2 Cross-Site Scripting (XSS)

**Problema:** Output não escapado refletido na página.

**Soluções:**

1. **Escapar HTML**
```python
from html import escape
safe_output = escape(user_input)
```

2. **Content Security Policy**
```python
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

3. **Validação de Input**
```python
import re
def sanitize_input(user_input):
    return re.sub(r'[<>]', '', user_input)
```

**Impacto:** Previne execução de scripts maliciosos

---

### 5.3 Sensitive Data Exposure

**Problema:** Arquivos sensíveis acessíveis publicamente.

**Soluções:**

1. **Configuração de Servidor**
```apache
<Files ".env">
    Require all denied
</Files>
```

2. **Mover Arquivos Sensíveis**
```bash
# Mover para fora do webroot
mv .env /var/app/config/.env
```

3. **Permissões de Arquivo**
```bash
chmod 600 /var/app/config/.env
```

**Impacto:** Previne vazamento de credenciais
---

## 6. Conclusões

### 6.1 Limitações Identificadas

- Scans com ferramentas externas são lentos (10-20 min)
- Detecção de false positives requer validação manual
- Requer permissão para executar Nmap (sudo)
- Limitado a testes de caixa-preta

### 6.2 Trabalhos Futuros

- Implementar análise heurística avançada
- Adicionar machine learning para reduzir false positives
- Criar sistema de autenticação para múltiplos usuários
- Implementar histórico de scans e comparação temporal
- Adicionar suporte a autenticação em aplicações testadas
- Integrar com mais ferramentas (Burp Suite API, OWASP ZAP)

---

## 7. Referências

1. OWASP Top 10 - 2021: https://owasp.org/Top10/
2. OWASP Testing Guide v4: https://owasp.org/www-project-web-security-testing-guide/
3. Nmap Network Scanning: https://nmap.org/book/
4. Nikto Web Scanner: https://github.com/sullo/nikto
5. Python Requests Documentation: https://requests.readthedocs.io/
6. Flask Web Framework: https://flask.palletsprojects.com/

---

## Anexos

### Exemplos de Relatórios
Ver arquivos:
- `docs/exemplo_relatorio_testphp.json`
- `docs/exemplo_relatorio_zero.json`

### Screenshots
Ver diretório:
- `docs/screenshots/`

### Vídeo Demonstrativo
Link: 