#!/bin/bash

echo -e "\n\033[95m╔════════════════════════════════════════════════╗"
echo -e   "║        saudadeDaEx — Instalador Oficial        ║"
echo -e   "╚════════════════════════════════════════════════╝\033[0m\n"

# ===== CHECK ROOT =====
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[31m[ERRO]\033[0m Rode como root:"
    echo "sudo ./install.sh"
    exit 1
fi

# ===== UPDATE =====
echo -e "\033[36m[1/6] Atualizando pacotes...\033[0m"
apt update -y

# ===== INSTALAR DEPENDÊNCIAS =====
echo -e "\033[36m[2/6] Instalando dependências do sistema...\033[0m"
apt install -y nmap nikto whatweb python3-pip python3-venv

# ===== COPIAR ARQUIVOS =====
echo -e "\033[36m[3/6] Criando diretório do SaudadeDaEx...\033[0m"
mkdir -p /opt/saudade
cp saudadeDaEx.py /opt/saudade/
cp interpreter.py /opt/saudade/

# ===== CRIAR AMBIENTE VIRTUAL =====
echo -e "\033[36m[4/6] Criando ambiente virtual...\033[0m"
python3 -m venv /opt/saudade/venv

# ===== INSTALAR DEPENDÊNCIAS PYTHON =====
echo -e "\033[36m[5/6] Instalando dependências Python...\033[0m"
source /opt/saudade/venv/bin/activate
pip install --upgrade pip
pip install bs4 lxml

# ===== CRIAR COMANDO GLOBAL =====
echo -e "\033[36m[6/6] Criando comando global 'saudade'...\033[0m"

echo '#!/bin/bash
source /opt/saudade/venv/bin/activate
python3 /opt/saudade/saudadeDaEx.py "$@"' > /usr/local/bin/saudade

chmod +x /usr/local/bin/saudade

# ===== FINAL =====
echo ""
echo -e "\033[32m[✓] Instalação concluída com sucesso!\033[0m"
echo -e "\033[35mVocê já pode usar o comando:\033[0m"
echo -e "\033[36m   saudade\033[0m"
echo ""
