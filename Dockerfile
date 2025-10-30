# Imagem base Python
FROM python:3.9-slim

# Metadados
LABEL maintainer="seu-email@example.com"
LABEL description="Web Security Scanner - Ferramenta de Teste de Segurança"
LABEL version="1.0"

# Definir diretório de trabalho
WORKDIR /app

# Copiar arquivos de dependências
COPY requirements.txt .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fonte
COPY src/ ./src/
COPY docs/ ./docs/

# Criar diretório para relatórios
RUN mkdir -p /app/reports

# Variável de ambiente para Python não criar arquivos .pyc
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Definir o PATH para incluir o diretório src
ENV PYTHONPATH=/app

# Expor porta (caso queira adicionar interface web no futuro)
EXPOSE 5000

# Comando padrão
ENTRYPOINT ["python", "src/scanner.py"]

# Exemplo de uso:
# docker build -t web-security-scanner .
# docker run --rm web-security-scanner http://testphp.vulnweb.com
# docker run --rm -v $(pwd)/reports:/app/reports web-security-scanner http://testphp.vulnweb.com