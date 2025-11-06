# Web Security Scanner

Este scanner realiza testes automatizados em aplicações web para detectar vulnerabilidades de segurança. O projeto combina técnicas próprias de detecção com integração de ferramentas profissionais (Nmap, Nikto) para fornecer uma análise completa de segurança.

**Características principais:**
- Detecção de 7 tipos de vulnerabilidades implementadas
- Integração com ferramentas de mercado (Nmap, Nikto)
- Interface de linha de comando
- Interface web com Flask
- Relatórios em formato JSON
- Nomenclatura incremental automática de arquivos

---
## Instalação

### Passo 1: Clonar o Repositório

```bash
git clone https://github.com/vivsoliveira/seguranca_web.git # para windows
cd web-security-scanner
```

```bash
git clone git@github.com:vivsoliveira/seguranca_web.git # para linux
cd web-security-scanner
```

### Passo 2: Instalar Dependências Python

```bash
pip install -r src/requirements.txt
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y nmap nikto
```

---

## Como Usar

### Modo 1: Interface de Linha de Comando (CLI)

Execução básica:

```bash
python3 src/scanner.py <URL>
```

Exemplo:

```bash
python3 src/scanner.py http://testphp.vulnweb.com
```

**Fluxo de execução:**

1. O scanner inicia e exibe o banner
2. Valida a URL fornecida
3. Executa testes de segurança:
   - Verifica headers de segurança
   - Busca formulários na página
   - Testa cada formulário para vulnerabilidades
   - Verifica arquivos sensíveis expostos
4. Gera relatório JSON automaticamente

### Modo 2: Interface Web

Iniciar servidor web:

```bash
python3 src/web_interface.py
```

Acessar no navegador:

```
http://localhost:5000
```

### Modo 3: Apenas Ferramentas Externas

Para executar somente as ferramentas externas (nmap e nikto):

```bash
python3 src/tools_scanner.py <URL>
```

---

## Relatórios

### Formato JSON

Todos os relatórios são gerados automaticamente em formato JSON na pasta `reports/`.
Os arquivos seguem o padrão: `{dominio}{numero}.json`

---

## Vulnerabilidades Detectadas

### 1. XSS (Cross-Site Scripting)

**Severidade:** MÉDIA

**Como funciona:**
- Injeta payloads JavaScript em campos de formulário
- Verifica se o payload é refletido na resposta sem sanitização
- Detecta quando inputs aceitam código malicioso

**Payloads testados:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

**Impacto:**
Permite que atacantes executem código JavaScript no navegador de outros usuários, possibilitando roubo de sessões, redirecionamentos maliciosos e manipulação de conteúdo.

---

### 2. SQL Injection

**Severidade:** ALTA

**Como funciona:**
- Injeta payloads SQL em campos de formulário
- Detecta mensagens de erro SQL na resposta
- Identifica quando queries SQL são executadas sem sanitização

**Payloads testados:**
```sql
' OR '1'='1
' OR 1=1--
admin' --
' UNION SELECT NULL--
```

**Erros detectados:**
- sql syntax
- mysql_fetch
- you have an error in your sql
- warning: mysql
- unclosed quotation mark

**Impacto:**
Permite acesso não autorizado ao banco de dados, podendo resultar em vazamento de dados, modificação de registros ou até controle total do banco.

---

### 3. CSRF (Cross-Site Request Forgery)

**Severidade:** MÉDIA

**Como funciona:**
- Verifica se formulários POST possuem tokens CSRF
- Detecta ausência de proteção contra requisições forjadas
- Analisa presença de tokens como: csrf, token, _token, csrf_token, authenticity_token

**Impacto:**
Permite que atacantes executem ações em nome de usuários autenticados sem seu conhecimento ou consentimento.

---

### 4. Path Traversal / Directory Traversal

**Severidade:** ALTA

**Como funciona:**
- Tenta acessar arquivos do sistema através de inputs
- Injeta sequências de navegação de diretórios
- Detecta se arquivos sensíveis são expostos

**Payloads testados:**
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
```

**Indicadores de sucesso:**
- Conteúdo de /etc/passwd (Linux)
- Conteúdo de win.ini (Windows)
- Presença de: root:x:, [extensions], bin/bash

**Impacto:**
Permite acesso a arquivos do sistema operacional, podendo expor configurações sensíveis, senhas e informações críticas.

---

### 5. File Inclusion (LFI/RFI)

**Severidade:** ALTA

**Como funciona:**
- Testa Local File Inclusion (inclusão de arquivos locais)
- Testa Remote File Inclusion (inclusão de arquivos remotos)
- Verifica se a aplicação permite incluir arquivos arbitrários

**Payloads LFI testados:**
```
../../../../etc/passwd
/etc/passwd
C:\windows\system32\drivers\etc\hosts
php://filter/convert.base64-encode/resource=index.php
```

**Indicadores de sucesso:**
- root:x:
- daemon:
- <?php
- # localhost

**Impacto:**
Permite execução de código arbitrário, leitura de arquivos sensíveis e potencial controle total da aplicação.

---

### 6. Sensitive Data Exposure

**Severidade:** ALTA/MÉDIA

**Como funciona:**
- Tenta acessar arquivos sensíveis comuns
- Verifica presença de informações confidenciais expostas
- Detecta configurações e backups acessíveis

**Arquivos testados:**
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

**Padrões sensíveis detectados:**
- password
- api_key
- secret
- db_password
- mysql, postgres, mongodb
- aws_access
- private_key

**Impacto:**
Expõe credenciais, chaves de API, configurações de banco de dados e outras informações críticas que podem facilitar ataques mais graves.

---

### 7. Insecure Headers

**Severidade:** BAIXA

**Como funciona:**
- Verifica presença de headers de segurança HTTP
- Identifica headers ausentes que protegem contra ataques

**Headers verificados:**
- X-Frame-Options (proteção contra Clickjacking)
- X-Content-Type-Options (proteção contra MIME sniffing)
- Strict-Transport-Security (força uso de HTTPS)
- Content-Security-Policy (proteção contra XSS)
- X-XSS-Protection (filtro XSS do navegador)

**Impacto:**
Facilita diversos tipos de ataques como Clickjacking, MIME sniffing e XSS quando headers apropriados não são configurados.

---

## Ferramentas Externas Integradas

### Nmap

**O que detecta:**
- Portas abertas e serviços expostos
- CVEs conhecidas (vulnerabilidades catalogadas)
- Versões de software desatualizadas
- Vulnerabilidades através de scripts NSE

**Tempo de execução:** Medio

---

### Nikto

**O que detecta:**
- Arquivos e diretórios perigosos expostos
- Configurações inseguras do servidor
- Headers ausentes ou mal configurados
- Backdoors e shells conhecidos
- Métodos HTTP perigosos habilitados

**Tempo de execução:** Longo

**Exemplo de detecção:**
- /admin/ directory indexing enabled
- Server allows TRACE method
- Outdated Apache version detected
- Missing security headers

---

## Executando Testes Unitários -- verficação da funcionalidade dos testes

```bash
python3 src/tests/test_scanner.py
```

É esperado que todos os testes passem sem erros.

---

### Erro: "URL inválida"

Certifique-se que a URL começa com http:// ou https://

```bash
# Incorreto
python3 src/scanner.py example.com

# Correto
python3 src/scanner.py http://example.com
```