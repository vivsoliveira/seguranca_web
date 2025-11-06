#!/bin/bash

echo "Instalação de Ferramentas de Segurança"
echo "=========================================="
echo ""

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para verificar comando
check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}${NC} $1 já instalado"
        return 0
    else
        echo -e "${RED}${NC} $1 não instalado"
        return 1
    fi
}

# Função para instalar
install_tool() {
    echo -e "${YELLOW}→${NC} Instalando $1..."
    sudo apt install -y $1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${NC} $1 instalado com sucesso!"
    else
        echo -e "${RED}${NC} Erro ao instalar $1"
    fi
}

# Verificar sistema operacional
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${YELLOW}${NC}  Este script é para Linux (Ubuntu/Debian)"
    echo "Para macOS, use: brew install nmap nikto whatweb"
    echo "Para Windows, consulte TOOLS_SETUP.md"
    exit 1
fi

echo "Verificando ferramentas..."
echo ""

# Verificar cada ferramenta
NMAP_INSTALLED=false
NIKTO_INSTALLED=false
WHATWEB_INSTALLED=false

if check_command nmap; then
    NMAP_INSTALLED=true
fi

if check_command nikto; then
    NIKTO_INSTALLED=true
fi

if check_command whatweb; then
    WHATWEB_INSTALLED=true
fi

echo ""

# Perguntar se deseja instalar
if [ "$NMAP_INSTALLED" = false ] || [ "$NIKTO_INSTALLED" = false ] || [ "$WHATWEB_INSTALLED" = false ]; then
    echo -e "${YELLOW}Algumas ferramentas não estão instaladas.${NC}"
    read -p "Deseja instalar agora? (s/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        echo ""
        echo "Atualizando lista de pacotes..."
        sudo apt update
        
        echo ""
        
        if [ "$NMAP_INSTALLED" = false ]; then
            install_tool nmap
        fi
        
        if [ "$NIKTO_INSTALLED" = false ]; then
            install_tool nikto
        fi
        
        if [ "$WHATWEB_INSTALLED" = false ]; then
            install_tool whatweb
        fi
        
        echo ""
        echo "=========================================="
        echo -e "${GREEN}Instalação concluída!${NC}"
    else
        echo ""
        echo "Instalação cancelada."
        echo "Para instalar manualmente:"
        echo "  sudo apt install nmap nikto whatweb"
    fi
else
    echo -e "${GREEN}Todas as ferramentas já estão instaladas!${NC}"
fi

echo ""
echo "Verificando versões:"
echo ""

if command -v nmap &> /dev/null; then
    echo "Nmap: $(nmap --version | head -1)"
fi

if command -v nikto &> /dev/null; then
    echo "Nikto: $(nikto -Version 2>&1 | head -1)"
fi

if command -v whatweb &> /dev/null; then
    echo "WhatWeb: $(whatweb --version 2>&1 | head -1)"
fi

echo ""
echo "=========================================="
echo "Para testar, execute:"
echo "  python3 src/tools_scanner.py http://testphp.vulnweb.com"
echo ""