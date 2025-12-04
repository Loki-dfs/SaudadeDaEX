TOOL_NAME="saudadeDaEx"
COMMAND_NAME="saudade"

RAW_URL="https://raw.githubusercontent.com/Loki-dfs/SaudadeDaEX/main/saudadeDaEx.py"

INSTALL_DIR="/usr/local/bin"
SCRIPT_PATH="$INSTALL_DIR/$COMMAND_NAME"

# CORES
BLUE="\033[34m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"


echo -e "${BLUE}"
echo "  ───────────────────────────────────────────────"
echo "          INSTALADOR OFICIAL — SaudadeDaEx        "
echo "  ───────────────────────────────────────────────"
echo -e "${RESET}"


# ==========================
# VERIFICAR ROOT
# ==========================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERRO]${RESET} Execute como root:"
    echo "sudo bash install.sh"
    exit 1
fi


# ==========================
# VERIFICAR DEPENDÊNCIAS
# ==========================
echo -e "${YELLOW}[•] Verificando dependências...${RESET}"

DEPS=("python3" "curl" "nmap" "nikto" "whatweb")

for dep in "${DEPS[@]}"; do
    if ! command -v $dep >/dev/null 2>&1; then
        echo -e "${RED}[FALTA]${RESET} $dep não encontrado."
        FALTANDO=1
    else
        echo -e "${GREEN}[OK]${RESET} $dep encontrado."
    fi
done

if [[ $FALTANDO -eq 1 ]]; then
    echo -e "${RED}\nInstale os pacotes acima antes de continuar.${RESET}"
    exit 1
fi


# ==========================
# BAIXAR SCRIPT
# ==========================
echo -e "\n${YELLOW}[•] Baixando o SaudadeDaEx...${RESET}"

curl -fsSL "$RAW_URL" -o "$SCRIPT_PATH"

if [[ $? -ne 0 ]]; then
    echo -e "${RED}[ERRO] Falha ao baixar o arquivo!${RESET}"
    exit 1
fi


# ==========================
# PERMISSÕES
# ==========================
chmod +x "$SCRIPT_PATH"


# ==========================
# FINAL
# ==========================
echo ""
echo -e "${GREEN}[✔] SaudadeDaEx instalado com sucesso!${RESET}"
echo ""
echo "Para executar, use:"
echo -e "${BLUE}saudade${RESET}"
echo ""
echo "Local de instalação:"
echo "$SCRIPT_PATH"
echo ""
echo -e "${GREEN}Bom uso 🔥${RESET}"
