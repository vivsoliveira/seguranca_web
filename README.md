# Web Security Scanner

Este scanner implementa uma solução automatizada para análise de vulnerabilidades em aplicações web. O sistema integra técnicas proprietárias de detecção com ferramentas profissionais consolidadas (Nmap, Nikto), proporcionando uma avaliação abrangente da superfície de ataque.

**Características principais:**
- Implementação de 7 categorias de testes de penetração
- Integração nativa com ferramentas de análise de segurança (Nmap, Nikto)
- Interface CLI (Command Line Interface)
- Interface web implementada com framework Flask
- Geração de relatórios estruturados em formato JSON
- Sistema automatizado de nomenclatura incremental para artefatos de saída

---
## Instalação

### Passo 1: Clonagem do Repositório

```bash
git clone https://github.com/vivsoliveira/seguranca_web.git # Windows
cd web-security-scanner
```

```bash
git clone git@github.com:vivsoliveira/seguranca_web.git # Linux/Unix
cd web-security-scanner
```

### Passo 2: Instalação de Dependências

**Linux/Unix:**
```bash
sudo apt update
sudo apt install -y nmap nikto
```

---

## Utilização

### Modo 1: Interface de Linha de Comando (CLI)

Sintaxe básica:

```bash
python3 src/scanner.py <URL>
```

Exemplo de execução:

```bash
python3 src/scanner.py http://testphp.vulnweb.com
```

**Fluxo operacional:**

1. Inicialização do scanner e exibição do banner informativo
2. Validação e parsing da URL fornecida
3. Execução sequencial dos testes de segurança:
   - Análise de headers de segurança HTTP
   - Enumeração de formulários na página-alvo
   - Teste de vulnerabilidades em cada formulário identificado
   - Verificação de exposição de arquivos sensíveis
4. Geração automática de relatório estruturado em JSON

### Modo 2: Interface Web

Inicialização do servidor web:

```bash
python3 src/interface.py
```

Acesso via navegador:

```
http://localhost:5000
```

### Modo 3: Execução Isolada de Ferramentas Externas

Execução exclusiva das ferramentas de terceiros (Nmap e Nikto):

```bash
python3 src/tools_scanner.py <URL>
```

Exemplo de utilização:

```bash
python3 src/tools_scanner.py http://testphp.vulnweb.com
```
---

## Relatórios

### Estrutura dos Artefatos de Saída

Todos os relatórios são gerados automaticamente em formato JSON no diretório `reports/`.
A nomenclatura dos arquivos segue o padrão: `{dominio}{numero_sequencial}.json`

---

## Taxonomia de Vulnerabilidades Detectadas

### 1. Cross-Site Scripting (XSS)

**Classificação de Severidade:** MÉDIA

**Metodologia de Detecção:**
- Injeção de payloads JavaScript em campos de entrada de formulários
- Análise da resposta HTTP para identificar reflexão não-sanitizada do payload
- Detecção de ausência de encoding/escaping de caracteres especiais

**Vetores de Ataque Testados:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

**Análise de Impacto:**
Exploração permite execução arbitrária de código JavaScript no contexto do navegador da vítima, possibilitando sequestro de sessões (session hijacking), redirecionamento para domínios maliciosos e manipulação do DOM (Document Object Model).

---

### 2. SQL Injection (SQLi)

**Classificação de Severidade:** ALTA

**Metodologia de Detecção:**
- Injeção de payloads SQL em parâmetros de entrada
- Análise de mensagens de erro SGBD (Sistema Gerenciador de Banco de Dados) na resposta
- Identificação de execução de queries SQL sem parametrização adequada

**Vetores de Ataque Testados:**
```sql
' OR '1'='1
' OR 1=1--
admin' --
' UNION SELECT NULL--
```

**Assinaturas de Erro Detectadas:**
- sql syntax
- mysql_fetch
- you have an error in your sql
- warning: mysql
- unclosed quotation mark

**Análise de Impacto:**
Exploração permite acesso não-autorizado ao banco de dados, podendo resultar em exfiltração de dados sensíveis, modificação de registros, bypass de autenticação ou comprometimento total do SGBD através de escalação de privilégios.

---

### 3. Cross-Site Request Forgery (CSRF)

**Classificação de Severidade:** MÉDIA

**Metodologia de Detecção:**
- Verificação da presença de tokens anti-CSRF em formulários com método POST
- Análise de mecanismos de proteção contra requisições forjadas
- Busca por tokens de validação: csrf, token, _token, csrf_token, authenticity_token

**Análise de Impacto:**
Exploração permite que atacantes executem ações state-changing em nome de usuários autenticados sem seu consentimento explícito, possibilitando modificação de dados, transações não-autorizadas e comprometimento de integridade.

---

### 4. Path Traversal / Directory Traversal

**Classificação de Severidade:** ALTA

**Metodologia de Detecção:**
- Tentativa de acesso a recursos do sistema de arquivos através de parâmetros de entrada
- Injeção de sequências de navegação hierárquica de diretórios
- Análise da resposta para identificar exposição de arquivos sensíveis do sistema operacional

**Vetores de Ataque Testados:**
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
```

**Indicadores de Exploração Bem-Sucedida:**
- Conteúdo do arquivo /etc/passwd (sistemas Unix/Linux)
- Conteúdo do arquivo win.ini (sistemas Windows)
- Presença de padrões: root:x:, [extensions], bin/bash

**Análise de Impacto:**
Exploração permite acesso arbitrário ao sistema de arquivos, possibilitando leitura de arquivos de configuração, exposição de credenciais, vazamento de código-fonte e potencial escalação de privilégios.

---

### 5. File Inclusion (LFI/RFI)

**Classificação de Severidade:** ALTA

**Metodologia de Detecção:**
- Teste de Local File Inclusion (inclusão de arquivos locais do servidor)
- Teste de Remote File Inclusion (inclusão de arquivos de servidores remotos)
- Análise da capacidade da aplicação de processar arquivos arbitrários

**Vetores de Ataque LFI Testados:**
```
../../../../etc/passwd
/etc/passwd
C:\windows\system32\drivers\etc\hosts
php://filter/convert.base64-encode/resource=index.php
```

**Indicadores de Exploração Bem-Sucedida:**
- root:x:
- daemon:
- <?php
- # localhost

**Análise de Impacto:**
Exploração permite execução remota de código arbitrário (RCE), leitura de arquivos sensíveis do sistema, possível comprometimento total da aplicação e do servidor subjacente.

---

### 6. Sensitive Data Exposure

**Classificação de Severidade:** ALTA/MÉDIA

**Metodologia de Detecção:**
- Enumeração de caminhos comuns para arquivos sensíveis
- Análise da resposta HTTP para identificar exposição de informações confidenciais
- Detecção de arquivos de configuração, backups e repositórios acessíveis publicamente

**Recursos Testados:**
```
/.env
/config.php
/wp-config.php
/database.yml
/.git/config
/backup.sql
/phpinfo.php
/admin
/robots.txt
/.DS_Store
```

**Padrões Sensíveis Identificados:**
- password
- api_key
- secret
- db_password
- mysql, postgres, mongodb
- aws_access
- private_key

**Análise de Impacto:**
Exposição de credenciais de acesso, chaves de API, strings de conexão de banco de dados e outras informações críticas que facilitam vetores de ataque subsequentes de maior severidade.

---

### 7. Insecure HTTP Headers

**Classificação de Severidade:** BAIXA

**Metodologia de Detecção:**
- Análise de headers de resposta HTTP
- Identificação de ausência de headers de segurança recomendados
- Verificação de conformidade com best practices de hardening HTTP

**Headers de Segurança Analisados:**
- X-Frame-Options (mitigação de ataques de Clickjacking)
- X-Content-Type-Options (prevenção de MIME type sniffing)
- Strict-Transport-Security (HSTS - aplicação forçada de HTTPS)
- Content-Security-Policy (CSP - mitigação de XSS e injeção de dados)
- X-XSS-Protection (ativação de filtros XSS do navegador)

**Análise de Impacto:**
Ausência de headers apropriados facilita múltiplos vetores de ataque incluindo Clickjacking, MIME confusion attacks, downgrade de protocolo e Cross-Site Scripting quando mecanismos de defesa em profundidade não são implementados.

---

## Ferramentas Externas Integradas

### Nmap (Network Mapper)

**Capacidades de Detecção:**
- Enumeração de portas TCP/UDP abertas e serviços associados
- Identificação de CVEs (Common Vulnerabilities and Exposures) conhecidas
- Detecção de versões de software desatualizadas
- Execução de scripts NSE (Nmap Scripting Engine) para testes especializados

**Complexidade Temporal:** Média

---

### Nikto

**Capacidades de Detecção:**
- Enumeração de recursos e diretórios potencialmente perigosos
- Identificação de configurações inseguras do servidor web
- Análise de headers HTTP ausentes ou mal-configurados
- Detecção de backdoors e web shells conhecidos
- Verificação de métodos HTTP potencialmente perigosos

**Complexidade Temporal:** Alta

**Exemplos de Detecções:**
- Directory listing habilitado em /admin/
- Método HTTP TRACE permitido (vulnerável a XST)
- Versão desatualizada do Apache Server detectada
- Headers de segurança ausentes ou mal-configurados

---

## Testes Unitários

Execução da suite de testes:

```bash
python3 src/tests/test_scanner.py
```

O comportamento esperado é a conclusão bem-sucedida de todos os casos de teste sem exceções.

---

## Troubleshooting

### Erro: "URL inválida"

Certifique-se de que a URL inclui o esquema de protocolo (http:// ou https://)

```bash
# Sintaxe incorreta
python3 src/scanner.py example.com

# Sintaxe correta
python3 src/scanner.py http://example.com
```

---

## Recursos Adicionais

**Demonstração em vídeo:** [https://youtu.be/2BzHt9pSgxQ]
