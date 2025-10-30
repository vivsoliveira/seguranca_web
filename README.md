# Web Security Scanner - Conceito C

Ferramenta de varredura de segurança para aplicações web, focada na detecção de vulnerabilidades XSS e SQL Injection.

## 📋 Funcionalidades

- ✅ Varredura simples de URLs e formulários
- ✅ Detecção de XSS (Cross-Site Scripting)
- ✅ Detecção de SQL Injection
- ✅ Interface de linha de comando com cores
- ✅ Relatórios em múltiplos formatos (TXT, JSON, CSV, Markdown)
- ✅ Testes unitários automatizados
- ✅ CI/CD com GitHub Actions
- ✅ Containerização com Docker

## 🏗️ Estrutura do Projeto

```
web-security-scanner/
├── src/
│   ├── scanner.py              # Scanner principal
│   ├── report_generator.py     # Gerador de relatórios
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py          # Funções auxiliares
│   └── requirements.txt        # Dependências
├── tests/
│   └── test_scanner.py         # Testes unitários
├── docs/
│   ├── architecture_diagram.png
│   └── flowchart.pdf
├── .github/
│   └── workflows/
│       └── security_scan.yml   # GitHub Actions
├── reports/                     # Relatórios gerados (criado automaticamente)
├── Dockerfile                   # Container Docker
└── README.md                    # Este arquivo
```

## 🔧 Instalação

### Opção 1: Instalação Local

```bash
# Clone o repositório
git clone <seu-repositorio>
cd web-security-scanner

# Instale as dependências
pip install -r requirements.txt
```

### Opção 2: Docker

```bash
# Build da imagem
docker build -t web-security-scanner .

# Executar
docker run --rm web-security-scanner http://testphp.vulnweb.com
```

## 🚀 Como Usar

### Uso Básico

```bash
python src/scanner.py <URL_ALVO>
```

### Com Formato de Relatório Específico

```bash
# Relatório em JSON
python src/scanner.py http://testphp.vulnweb.com --format json

# Relatório em CSV
python src/scanner.py http://testphp.vulnweb.com --format csv

# Relatório em Markdown
python src/scanner.py http://testphp.vulnweb.com --format md
```

### Usando Docker com Volume para Relatórios

```bash
docker run --rm -v $(pwd)/reports:/app/reports web-security-scanner http://testphp.vulnweb.com
```

## 🧪 Executar Testes

```bash
# Executar todos os testes
python tests/test_scanner.py

# Com pytest (mais detalhado)
pytest tests/ -v

# Com coverage
pytest tests/ --cov=src --cov-report=html
```

## 📊 Formatos de Relatório

### TXT (Texto)
Relatório formatado para leitura no terminal

### JSON
Dados estruturados para integração com outras ferramentas

### CSV
Formato tabular para análise em Excel/planilhas

### Markdown
Documentação formatada para GitHub/GitLab

## 📈 Exemplo de Saída

```
╔═══════════════════════════════════════════════════════╗
║          Web Security Scanner - Conceito C            ║
║              Ferramenta de Testes de Segurança        ║
╚═══════════════════════════════════════════════════════╝

[*] Iniciando varredura em: http://testphp.vulnweb.com
[*] Hora de início: 2025-10-30 14:30:00

[+] 3 formulário(s) encontrado(s)

[*] Testando formulário 1/3

╔═══════════════════════════════════════════════════════╗
║ VULNERABILIDADE DETECTADA
╚═══════════════════════════════════════════════════════╝

Tipo: XSS (Cross-Site Scripting)
Severidade: MÉDIA
URL: http://testphp.vulnweb.com/search.php
Método: GET
Parâmetro: searchFor
Payload: <script>alert('XSS')</script>

[+] Varredura concluída!
[*] Duração: 5.43 segundos
[*] Total de vulnerabilidades encontradas: 2

[+] Relatório salvo em: reports/report_20251030_143000.txt
```

## 🎯 Vulnerabilidades Detectadas

### XSS (Cross-Site Scripting)
- Payloads testados: `<script>`, `<img>`, `javascript:`
- Detecta reflexão de scripts na resposta
- Severidade: MÉDIA

### SQL Injection
- Payloads testados: `' OR '1'='1`, `UNION SELECT`, etc.
- Detecta mensagens de erro SQL
- Severidade: ALTA

## 🔒 Sites para Teste

**IMPORTANTE**: Apenas teste em sites que você tem permissão!

### Sites Vulneráveis Intencionalmente (Legal):
- http://testphp.vulnweb.com
- http://www.webscantest.com
- http://zero.webappsecurity.com
- https://portswigger.net/web-security (requer cadastro)

### ⚠️ AVISO LEGAL
Esta ferramenta é **apenas para fins educacionais**. Testar segurança de sites sem autorização é **ilegal**. Use apenas em:
- Seus próprios sites
- Ambientes de teste autorizados
- Sites de prática dedicados

## 🔄 CI/CD Pipeline

O projeto inclui GitHub Actions para:
- ✅ Execução automática de testes
- ✅ Verificação de qualidade de código (linting)
- ✅ Build da imagem Docker
- ✅ Auditoria de segurança das dependências

## 📦 Dependências

```
requests>=2.31.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
colorama>=0.4.6
```

## 🚀 Roadmap (Próximas Versões)

### Para Conceito B:
- [ ] Detecção de CSRF
- [ ] Detecção de Directory Traversal
- [ ] Interface web básica
- [ ] Integração com OWASP ZAP API

### Para Conceito A:
- [ ] Dashboard interativo
- [ ] Sistema de priorização por severidade
- [ ] Análise heurística avançada
- [ ] Autenticação multi-usuário
- [ ] Banco de dados para histórico

## 📝 Documentação Técnica

### Arquitetura
O sistema segue uma arquitetura modular:

1. **Scanner Core** (`scanner.py`): Lógica principal de varredura
2. **Report Generator** (`report_generator.py`): Geração de relatórios
3. **Utils** (`utils/`): Funções auxiliares reutilizáveis
4. **Tests** (`tests/`): Testes automatizados

### Metodologia de Testes

1. **Coleta de Formulários**: Identifica todos os forms na página
2. **Extração de Parâmetros**: Mapeia inputs e métodos HTTP
3. **Injeção de Payloads**: Testa cada parâmetro com payloads maliciosos
4. **Análise de Resposta**: Verifica se vulnerabilidade foi explorada
5. **Geração de Relatório**: Documenta achados

## 👥 Autores

- [Seu Nome] - [Seu Email]
- [Nome do Colega] - [Email do Colega]

**Instituição**: Insper  
**Curso**: Tecnologias Hackers  
**Professores**: Rodolfo Avelino e João Eduardo
