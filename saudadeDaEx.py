#!/usr/bin/env python3

import os
import sys
import subprocess
import datetime
import threading
import time
import re
import platform
import shutil
import urllib.request
import html as html_lib

# ==============================
# CONFIG
# ==============================
TOOL_NAME = "saudadeDaEx"
VERSION = "0.3"
NMAP = shutil.which("nmap") or "nmap"
NIKTO = shutil.which("nikto") or "nikto"
WHATWEB = shutil.which("whatweb") or None
OPEN_FOLDER = True

# ==============================
# ANSI COLORS
# ==============================
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

def banner():
    print(f"""{RED}{BOLD}
  ____                 _           _        ____  
 / ___|  __ _ _ __ ___| |__     __| |      |  _ \ 
 \___ \ / _` | '__/ _ \ '_ \   / _` |      | | | |
  ___) | (_| | | |  __/ |_) | | (_| |   _  | |_| |
 |____/ \__,_|_|  \___|_.__/   \__,_|  (_) |____/ 

        saudadeDaEx — Scanner Profissional
    {RESET}
""")



def check_dependencies():
    missing = []
    if shutil.which("nmap") is None:
        missing.append("nmap")
    if shutil.which("nikto") is None:
        missing.append("nikto")
    # WhatWeb is optional — não adicionamos na lista de faltantes
    return missing

def run_cmd(cmd, timeout=None):
    try:
        res = subprocess.run(cmd, shell=True, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout)
        return res.stdout + res.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] O comando demorou demais."

def spinner(thread, text="Processando..."):
    spinner_chars = ["|","/","-","\\"]
    i = 0
    while thread.is_alive():
        print(f"\r{YELLOW}{text} {spinner_chars[i % 4]}{RESET}", end="")
        time.sleep(0.12)
        i += 1
    print("\r" + " " * (len(text)+4), end="\r")

def open_folder(path):
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except:
        print(RED + "Falha ao abrir pasta." + RESET)

def safe_name(s):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", s)



# ---- NIKTO COMPLETO ----
def interpretar_nikto(txt):
    """
    Nikto moderno usa: + texto
    Qualquer linha iniciada com + é um achado
    """
    vulns = 0
    caminhos = 0

    for l in txt.splitlines():
        l = l.strip()

        # Nikto normalmente começa achados com "+ " (mais pode variar)
        if l.startswith("+"):
            vulns += 1

            # se houver caminho no texto
            if "/" in l:
                caminhos += 1

    return vulns, caminhos


def interpretar_nmap_site(txt):
    return re.findall(r"([0-9]+)/tcp\s+open", txt)

def interpretar_nmap_rede(txt):
    hosts = re.findall(r"Nmap scan report for ([0-9\.]+)", txt)
    portas = re.findall(r"([0-9]+)/tcp\s+open", txt)
    return hosts, portas


def gerar_html_resumo(pasta, alvo, modo, **stats):
    filename = f"{safe_name(alvo)}_resumo.html"
    path = os.path.join(pasta, filename)

    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # construir bloco de tecnologias se houver
    tech_html = ""
    tecnologias = stats.get("tecnologias", [])
    if tecnologias:
        tech_list = "".join(f"<li>{html_lib.escape(t)}</li>" for t in tecnologias)
        tech_html = f"""
        <h2>Tecnologias detectadas</h2>
        <div class="box">
            <ul>
            {tech_list}
            </ul>
        </div>
        """

    if modo == "site":
        vulns = stats.get("vulns", 0)
        portas = len(stats.get("portas", []))
        caminhos = stats.get("caminhos", 0)

        summary = f"""
        Foram encontradas <b>{vulns}</b> vulnerabilidades.
        <br>Portas abertas: <b>{portas}</b>
        <br>Diretórios sensíveis: <b>{caminhos}</b>
        """

    else:
        hosts = len(stats.get("hosts", []))
        portas = len(stats.get("portas", []))

        summary = f"""
        Hosts ativos detectados: <b>{hosts}</b>
        <br>Portas abertas totais: <b>{portas}</b>
        """

    html = f"""
    <html>
    <head>
        <meta charset='utf-8'>
        <title>Resumo - {html_lib.escape(alvo)}</title>
        <style>
            body {{ background:#f7f7f7; font-family:Arial; padding:20px; }}
            .box {{ background:white; padding:20px; border-radius:10px;
                   box-shadow:0 0 10px rgba(0,0,0,0.15); }}
            ul {{ margin:0 0 0 18px; }}
        </style>
    </head>
    <body>
        <h1>Resumo da varredura — {html_lib.escape(alvo)}</h1>
        <small>Gerado por {TOOL_NAME} em {timestamp}</small>
        <div class="box">
            <p>{summary}</p>
        </div>

        {tech_html}

        <h2>Recomendações Gerais</h2>
        <ul>
            <li>Atualize o servidor.</li>
            <li>Remova diretórios sensíveis expostos.</li>
            <li>Feche portas desnecessárias.</li>
            <li>Proteja servidores com firewall e regras adequadas.</li>
        </ul>
    </body>
    </html>
    """

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path

# ------------------ DETECÇÃO DE TECNOLOGIAS ------------------

def detectar_tecnologias(host, pasta):
    """
    Retorna lista de tecnologias detectadas.
    Usa WhatWeb se disponível, caso contrário usa um fallback básico (headers + meta generator).
    Salva raw output em pasta (whatweb_raw.txt ou tech_raw.txt)
    """
    techs = []

    host_url = host
    # garantir esquema para requests fallback
    if not re.match(r"^https?://", host_url):
        host_url = "http://" + host_url

    if WHATWEB:
        try:
            out = run_cmd(f"{WHATWEB} -q {host_url}")
            # salvar raw
            with open(os.path.join(pasta, "whatweb_raw.txt"), "w", encoding="utf-8") as f:
                f.write(out)
            # parse básico: [Tech][Another]
            parts = out.split("[")
            for p in parts[1:]:
                tech = p.split("]")[0].strip()
                if tech and tech not in techs:
                    techs.append(tech)
            return techs
        except Exception:
            pass

    # fallback: pegar headers + meta generator
    try:
        req = urllib.request.Request(host_url, headers={"User-Agent": "Mozilla/5.0 (saudadeDaEx)"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = resp.headers
            body = resp.read(100000).decode(errors="ignore")  # limitar leitura
            # salvar raw
            with open(os.path.join(pasta, "tech_raw.txt"), "w", encoding="utf-8") as f:
                f.write("=== HEADERS ===\n")
                f.write(str(headers))
                f.write("\n\n=== HTML (primeiros 100KB) ===\n")
                f.write(body)

            # extrair algumas tecnologias comuns a partir dos headers/html
            server = headers.get("Server")
            if server:
                if server not in techs:
                    techs.append(f"Server: {server}")

            xpb = headers.get("X-Powered-By")
            if xpb and xpb not in techs:
                techs.append(f"X-Powered-By: {xpb}")

            # cookies (ex.: PHPSESSID)
            setcookie = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else headers.get("Set-Cookie")
            if setcookie:
                # detectar PHP, ASP
                sc_text = str(setcookie)
                if "PHPSESSID" in sc_text and "PHP" not in techs:
                    techs.append("PHP (cookie detected)")
                if "wordpress" in sc_text.lower() and "WordPress" not in techs:
                    techs.append("WordPress (cookie)")

            # meta generator
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
            if m:
                gen = m.group(1).strip()
                if gen and gen not in techs:
                    techs.append(f"Generator: {gen}")

            # procurar por padrões em body (jquery, react, wp-content)
            patterns = {
                "jQuery": r"jquery(?:\.min)?\.js",
                "React": r"react(?:[-\.]|/|>)",
                "Angular": r"angular(?:\.js|/)",
                "Vue.js": r"vue(?:\.min)?\.js",
                "WordPress": r"wp-content|wp-includes",
                "Drupal": r"drupal.settings",
                "Bootstrap": r"bootstrap(?:\.min)?\.css",
                "Express": r"X-Powered-By: Express"
            }
            for name, pat in patterns.items():
                if re.search(pat, body, re.IGNORECASE) and name not in techs:
                    techs.append(name)

    except Exception as e:
        # não foi possível conectar — não adiciona nada além de nota
        techs.append(f"(detector fallback falhou: {e})")

    return techs


def scan_site_turbo(host):
    nmap_out = ""
    nikto_out = ""
    techs = []

    def run_nmap():
        nonlocal nmap_out
        nmap_out = run_cmd(f"{NMAP} -T5 -F -n {host}")

    def run_nikto():
        nonlocal nikto_out
        check = run_cmd(f"{NMAP} -p80,443 -n {host}")
        if "open" in check:
            nikto_out = run_cmd(f"{NIKTO} -h {host} -Tuning x6")
        else:
            nikto_out = ""

    t1 = threading.Thread(target=run_nmap)
    t2 = threading.Thread(target=run_nikto)
    t1.start(); t2.start()
    while t1.is_alive() or t2.is_alive():
        for s in "|/-\\":
            print(f"\r{CYAN}Scan Turbo {s}{RESET}", end="")
            time.sleep(0.12)
    print("\r", end="")

    # detectar tecnologias (rápido) - run after threads to avoid extra wait
    techs = detectar_tecnologias(host, ".")  # pasta será substituída na main; salvamos later na pasta correta
    return nmap_out, nikto_out, techs

def scan_site_full(host):
    print(f"{YELLOW}Executando Nikto COMPLETO… Pode demorar.{RESET}\n")
    nmap_out = run_cmd(f"{NMAP} -sV -n {host}")
    nikto_out = run_cmd(f"{NIKTO} -h {host}")
    techs = detectar_tecnologias(host, ".")
    return nmap_out, nikto_out, techs

def scan_rede_turbo(alvo):
    return run_cmd(f"{NMAP} -T5 -F -n {alvo}")


def menu():
    banner()
    print(f"{CYAN}Versão: {VERSION}{RESET}\n")
    print(f"{GREEN}1){RESET} Scan SITE (TURBO)")
    print(f"{GREEN}2){RESET} Scan SITE (FULL)")
    print(f"{GREEN}3){RESET} Scan REDE (TURBO)")
    print(f"{GREEN}4){RESET} Atualizar SaudadeDaEx")
    print(f"{GREEN}5){RESET} Desinstalar SaudadeDaEx")
    print(f"{GREEN}6){RESET} Sair\n")
    return input(f"{CYAN}Escolha: {RESET}")


def confirm_auth():
    print(f"{YELLOW}\nVocê TEM autorização para escanear este alvo? (yes/no){RESET}")
    if input("> ").lower() not in ("yes", "y"):
        print(f"{RED}Operação abortada.{RESET}")
        sys.exit()


# ==============================
# UPDATE AUTOMÁTICO
# ==============================
def update_saudade():
    print(f"{CYAN}{BOLD}Verificando atualizações...{RESET}")

    INSTALL_PATH = "/usr/local/bin/saudade"
    RAW_URL = "https://raw.githubusercontent.com/Loki-dfs/SaudadeDaEX/main/saudadeDaEx.py"

    try:
        # baixar versão nova para memória
        print(f"{YELLOW}Baixando versão mais recente...{RESET}")
        response = urllib.request.urlopen(RAW_URL, timeout=10)
        new_code = response.read().decode("utf-8")

        if len(new_code) < 100:
            print(f"{RED}Erro: código remoto parece inválido!{RESET}")
            sys.exit()

        # escrever nova versão no arquivo instalado
        print(f"{YELLOW}Atualizando arquivo em:{RESET} {INSTALL_PATH}")
        with open(INSTALL_PATH, "w", encoding="utf-8") as f:
            f.write(new_code)

        os.chmod(INSTALL_PATH, 0o755)

        print(f"\n{GREEN}{BOLD}SaudadeDaEx atualizado com sucesso!{RESET}")
        print(f"{GREEN}Versão atualizada disponível agora com o comando:{RESET}")
        print(f"{CYAN}saudade{RESET}\n")

    except Exception as e:
        print(f"{RED}Falha ao atualizar: {e}{RESET}")

    sys.exit()


def main():
    deps = check_dependencies()
    if deps:
        print(f"{RED}Ferramentas faltando: {', '.join(deps)}{RESET}")
        sys.exit()

    while True:
        choice = menu()

        # UPDATE
        if choice == "4":
            update_saudade()
            continue

        # UNINSTALL
        if choice == "5":
            uninstall_saudade()
            continue

        # SAIR
        if choice == "6":
            print(f"{GREEN}Saindo…{RESET}")
            sys.exit()

        # opções inválidas
        if choice not in ("1", "2", "3"):
            print(f"{RED}Opção inválida.{RESET}")
            continue

        # CONFIRMAR AUTORIZAÇÃO
        confirm_auth()

        alvo = input(f"{CYAN}Digite o alvo:{RESET} ").strip()
        host = re.sub(r"^https?://", "", alvo).split("/")[0]

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pasta = f"saudade_{timestamp}"
        os.makedirs(pasta, exist_ok=True)

        print(f"{GREEN}\nPasta criada:{RESET} {pasta}\n")

        nmap_out = ""
        nikto_out = ""
        techs = []

        # EXECUÇÃO DOS TIPOS DE SCAN
        if choice == "1":
            print(f"{BLUE}Executando SITE TURBO…{RESET}")
            nmap_out, nikto_out, techs = scan_site_turbo(host)

        elif choice == "2":
            print(f"{BLUE}Executando SITE FULL…{RESET}")
            nmap_out, nikto_out, techs = scan_site_full(host)

        elif choice == "3":
            print(f"{BLUE}Executando REDE TURBO…{RESET}")
            nmap_out = scan_rede_turbo(host)
            nikto_out = ""
            techs = []

        # SALVAR BRUTOS
        with open(os.path.join(pasta, "nmap_raw.txt"), "w", encoding="utf-8") as f:
            f.write(nmap_out or "")

        if nikto_out:
            with open(os.path.join(pasta, "nikto_raw.txt"), "w", encoding="utf-8") as f:
                f.write(nikto_out or "")

        # SALVAR TECHNOLOGIAS RAW
        if choice in ("1", "2"):
            if WHATWEB:
                ww_out = run_cmd(f"{WHATWEB} -q http://{host}")
                with open(os.path.join(pasta, "whatweb_raw.txt"), "w", encoding="utf-8") as f:
                    f.write(ww_out or "")

                # Parse rápido
                if not techs:
                    parts = ww_out.split("[")
                    techs = []
                    for p in parts[1:]:
                        tech = p.split("]")[0].strip()
                        if tech and tech not in techs:
                            techs.append(tech)

            else:
                # fallback simples
                try:
                    url = "http://" + host if not re.match(r"^https?://", host) else host
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (saudadeDaEx)"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        headers = resp.headers
                        body = resp.read(100000).decode(errors="ignore")
                        with open(os.path.join(pasta, "tech_raw.txt"), "w", encoding="utf-8") as f:
                            f.write("=== HEADERS ===\n")
                            f.write(str(headers))
                            f.write("\n\n=== HTML (primeiros 100KB) ===\n")
                            f.write(body)
                except:
                    pass

        # INTERPRETAÇÃO E RESUMO
        if choice in ("1", "2"):
            portas = interpretar_nmap_site(nmap_out)
            vulns, caminhos = interpretar_nikto(nikto_out)

            resumo = gerar_html_resumo(
                pasta, alvo, "site",
                vulns=vulns, portas=portas, caminhos=caminhos, tecnologias=techs
            )

            print(f"{GREEN}{BOLD}Resumo:{RESET}")
            print(f"Vulnerabilidades: {RED}{vulns}{RESET}")
            print(f"Portas abertas: {CYAN}{len(portas)}{RESET}")
            print(f"Diretórios sensíveis: {MAGENTA}{caminhos}{RESET}\n")

            if techs:
                print(f"{GREEN}Tecnologias detectadas:{RESET}")
                for t in techs:
                    print(f" - {YELLOW}{t}{RESET}")
                print()
            else:
                print(f"{YELLOW}Nenhuma tecnologia detectada.{RESET}\n")

        else:
            hosts, portas = interpretar_nmap_rede(nmap_out)

            resumo = gerar_html_resumo(
                pasta, alvo, "rede",
                hosts=hosts, portas=portas
            )

            print(f"{GREEN}{BOLD}Resumo:{RESET}")
            print(f"Hosts ativos: {CYAN}{len(hosts)}{RESET}")
            print(f"Portas abertas (total): {MAGENTA}{len(portas)}{RESET}\n")

        print(f"{YELLOW}Relatório HTML salvo em:{RESET} {resumo}\n")

        if OPEN_FOLDER:
            if input(f"{CYAN}Abrir pasta agora? (y/n){RESET} ").lower() == "y":
                open_folder(pasta)

        if input(f"{CYAN}Rodar outro scan? (y/n){RESET} ").lower() != "y":
            print(f"{GREEN}Saindo…{RESET}")
            break

# ==============================
# UNINSTALL
# ==============================
def uninstall_saudade():
    print(f"{RED}{BOLD}Iniciando desinstalação do SaudadeDaEx...{RESET}\n")

    INSTALL_PATH = "/usr/local/bin/saudade"

    # remover comando global
    if os.path.exists(INSTALL_PATH):
        try:
            os.remove(INSTALL_PATH)
            print(f"{GREEN}[✓]{RESET} Comando removido: {INSTALL_PATH}")
        except:
            print(f"{RED}[X]{RESET} Não foi possível remover {INSTALL_PATH}")
    else:
        print(f"{YELLOW}[!]{RESET} O comando não estava instalado em {INSTALL_PATH}")

    # remover pastas de relatórios
    removed = 0
    for pasta in os.listdir("."):
        if pasta.startswith("saudade_"):
            try:
                shutil.rmtree(pasta)
                removed += 1
            except:
                pass

    print(f"{GREEN}[✓]{RESET} Pastas removidas: {removed}")

    # remover configs futuras
    HOME_CONFIG = os.path.expanduser("~/.saudade")
    if os.path.exists(HOME_CONFIG):
        try:
            shutil.rmtree(HOME_CONFIG)
            print(f"{GREEN}[✓]{RESET} Configurações removidas.")
        except:
            print(f"{RED}[X]{RESET} Não foi possível remover configs.")

    print(f"\n{GREEN}{BOLD}SaudadeDaEx removido do sistema.{RESET}")
    sys.exit()


# ==============================
# UPDATE AUTOMÁTICO (VERSÃO CORRETA)
# ==============================
def update_saudade():
    print(f"{CYAN}{BOLD}Verificando atualizações...{RESET}")

    INSTALL_PATH = "/usr/local/bin/saudade"
    RAW_URL = "https://raw.githubusercontent.com/Loki-dfs/SaudadeDaEX/main/saudadeDaEx.py"

    try:
        print(f"{YELLOW}Baixando versão mais recente...{RESET}")
        response = urllib.request.urlopen(RAW_URL, timeout=10)
        new_code = response.read().decode("utf-8")

        if len(new_code) < 100:
            print(f"{RED}Erro: código remoto parece inválido!{RESET}")
            sys.exit()

        print(f"{YELLOW}Atualizando arquivo em:{RESET} {INSTALL_PATH}")
        with open(INSTALL_PATH, "w", encoding="utf-8") as f:
            f.write(new_code)

        os.chmod(INSTALL_PATH, 0o755)

        print(f"\n{GREEN}{BOLD}SaudadeDaEx atualizado com sucesso!{RESET}")
        print(f"{GREEN}Use:{RESET} {CYAN}saudade{RESET}")

    except Exception as e:
        print(f"{RED}Falha ao atualizar: {e}{RESET}")

    sys.exit()


# ==============================
# ENTRYPOINT COM ARGUMENTOS
# ==============================
if __name__ == "__main__":

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()

        # HELP
        if arg in ("--help", "-h", "help"):
            print(f"""
{GREEN}{BOLD}SaudadeDaEx — Ajuda{RESET}

Comandos disponíveis:

  saudade                   → abre o menu  
  saudade --help            → mostra ajuda  
  saudade --version         → mostra a versão  
  saudade --update          → atualiza para a versão mais recente  
  saudade --uninstall       → remove completamente  
            """)
            sys.exit()

        # VERSION
        if arg in ("--version", "-v"):
            print(f"{GREEN}{BOLD}SaudadeDaEx versão {VERSION}{RESET}")
            sys.exit()

        # UPDATE
        if arg in ("--update", "update"):
            update_saudade()

        # UNINSTALL
        if arg in ("--uninstall", "-u", "uninstall"):
            uninstall_saudade()

        print(f"{RED}Comando desconhecido: {arg}{RESET}")
        sys.exit()

    # SEM ARGUMENTOS → roda o programa normal
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Interrompido pelo usuário.{RESET}")
        sys.exit()
