
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

# Import do interpreter (mantenha interpreter.py ao lado)
from interpreter import InterpreterEngine



TOOL_NAME = "saudadeDaEx"
VERSION = "0.5"
NMAP = shutil.which("nmap") or "nmap"
NIKTO = shutil.which("nikto") or "nikto"
WHATWEB = shutil.which("whatweb") or None
OPEN_FOLDER = True


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

PURPLE = "\033[95m"
MAGENTA = "\033[35m"  
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
WHITE = "\033[37m"



def _fmt(prefix: str, msg: str, color: str = WHITE):
    return f"{color}{prefix}{RESET} {msg}"

def info(msg: str):
    print(_fmt("[i]", msg, CYAN))

def warn(msg: str):
    print(_fmt("[!]", msg, YELLOW))

def ok(msg: str):
    print(_fmt("[✓]", msg, GREEN))

def err(msg: str):
    print(_fmt("[x]", msg, RED))

def banner():
    clear()
    print(f"""{PURPLE}{BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ███████╗ █████╗ ██╗   ██╗██████╗  █████╗ ██╗      █████╗  ██╗║
║   ██╔════╝██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔══██╗███║║
║   ███████╗███████║██║   ██║██║  ██║███████║██║     ███████║╚██║║
║   ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║     ██╔══██║ ██ ║
║   ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║ █ ║
║   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═╝║
║                                                                ║
║          saudadeDaEx                                           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝{RESET}
""")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def safe_name(s):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", s)


def run_cmd(cmd, timeout=None):
    try:
        res = subprocess.run(cmd, shell=True, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout)
        return (res.stdout or "") + (res.stderr or "")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] O comando demorou demais."
    except Exception as e:
        return f"[ERRO AO EXECUTAR] {e}"


class Spinner:
    def __init__(self, text="Processando", color=PURPLE):
        self.text = text
        self._stop = threading.Event()
        self.color = color
        self._t = None
        self._chars = ["⠁","⠂","⠄","⡀","⢀","⠠","⠐","⠈"]  # nicer spinner frames

    def start(self):
        self._stop.clear()
        self._t = threading.Thread(target=self._spin_loop, daemon=True)
        self._t.start()
        return self

    def stop(self):
        if self._t and self._t.is_alive():
            self._stop.set()
            self._t.join(timeout=1)

    def _spin_loop(self):
        i = 0
        while not self._stop.is_set():
            ch = self._chars[i % len(self._chars)]
            print(f"\r{self.color}{self.text} {ch}{RESET}", end="", flush=True)
            time.sleep(0.09)
            i += 1
        print("\r" + " " * (len(self.text) + 6), end="\r")

    
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()


def open_folder(path):
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        warn("Falha ao abrir pasta (verifique ambiente gráfico).")


def confirm_auth():
    print(f"{YELLOW}\nVocê TEM autorização para escanear este alvo? (yes/no){RESET}")
    if input("> ").lower() not in ("yes", "y"):
        err("Operação abortada.")
        sys.exit()



def interpretar_nikto(txt):
    """
    Versão simples: conta linhas que parecem achados.
    Mantido para compatibilidade com InterpreterEngine fallback.
    """
    vulns = 0
    caminhos = 0
    if not txt:
        return 0, 0
    for l in txt.splitlines():
        l = l.strip()
        if l.startswith("+"):
            vulns += 1
            if "/" in l:
                caminhos += 1
    return vulns, caminhos

def interpretar_nmap_site(txt):
    if not txt:
        return []
    return re.findall(r"([0-9]+)/tcp\s+open", txt)

def interpretar_nmap_rede(txt):
    if not txt:
        return [], []
    hosts = re.findall(r"Nmap scan report for ([0-9\.]+)", txt)
    portas = re.findall(r"([0-9]+)/tcp\s+open", txt)
    return hosts, portas


def gerar_html_resumo(pasta, alvo, modo, **stats):
    filename = f"{safe_name(alvo)}_resumo.html"
    path = os.path.join(pasta, filename)

    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
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
            body {{ background:#0f0b12; color:#e6e6f2; font-family:Arial,Helvetica,sans-serif; padding:20px; }}
            .box {{ background:#18121b; padding:20px; border-radius:10px; border:1px solid #2b1b2e;
                   box-shadow:0 0 10px rgba(0,0,0,0.6); }}
            a {{ color:#caa2ff; }}
            ul {{ margin:0 0 0 18px; }}
            h1,h2 {{ color:#ffd7ff; }}
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
            <li>Atualize o servidor e aplique patches.</li>
            <li>Remova diretórios sensíveis expostos.</li>
            <li>Feche portas desnecessárias e restrinja por firewall.</li>
            <li>Implemente monitoração e alertas.</li>
        </ul>
    </body>
    </html>
    """

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        warn(f"Falha ao salvar resumo HTML: {e}")
        return None

    return path


def detectar_tecnologias(host, pasta):
    """
    Detecta tecnologias via WhatWeb (se disponível) ou via fallback (headers + html patterns).
    Salva saídas brutas em pasta.
    """
    techs = []
    host_url = host
    if not re.match(r"^https?://", host_url):
        host_url = "http://" + host_url

    
    if WHATWEB:
        try:
            out = run_cmd(f"{WHATWEB} -q {host_url}")
            with open(os.path.join(pasta, "whatweb_raw.txt"), "w", encoding="utf-8") as f:
                f.write(out or "")
            parts = out.split("[")
            for p in parts[1:]:
                tech = p.split("]")[0].strip()
                if tech and tech not in techs:
                    techs.append(tech)
            return techs
        except Exception:
            pass

    
    try:
        req = urllib.request.Request(host_url, headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME})"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = resp.headers
            body = resp.read(100000).decode(errors="ignore")
            with open(os.path.join(pasta, "tech_raw.txt"), "w", encoding="utf-8") as f:
                f.write("=== HEADERS ===\n")
                f.write(str(headers))
                f.write("\n\n=== HTML (primeiros 100KB) ===\n")
                f.write(body or "")

            server = headers.get("Server")
            if server and server not in techs:
                techs.append(f"Server: {server}")
            xpb = headers.get("X-Powered-By")
            if xpb and xpb not in techs:
                techs.append(f"X-Powered-By: {xpb}")

            
            try:
                setcookie = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else headers.get("Set-Cookie")
            except Exception:
                setcookie = None
            if setcookie:
                sc_text = str(setcookie)
                if "PHPSESSID" in sc_text and "PHP" not in techs:
                    techs.append("PHP (cookie detected)")
                if "wordpress" in sc_text.lower() and "WordPress" not in techs:
                    techs.append("WordPress (cookie)")

            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body or "", re.IGNORECASE)
            if m:
                gen = m.group(1).strip()
                if gen and gen not in techs:
                    techs.append(f"Generator: {gen}")

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
                if re.search(pat, body or "", re.IGNORECASE) and name not in techs:
                    techs.append(name)
    except Exception as e:
        techs.append(f"(detector fallback falhou: {e})")

    return techs



def scan_site_turbo(host):
    """
    Scan rápido: Nmap rápido + Nikto (se portas 80/443 abertas) + WhatWeb (opcional).
    Retorna: nmap_out, nikto_out, techs, ww_out
    """
    nmap_out = ""
    nikto_out = ""
    techs = []
    ww_out = ""

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

    t1 = threading.Thread(target=run_nmap, daemon=True)
    t2 = threading.Thread(target=run_nikto, daemon=True)
    t1.start(); t2.start()

    with Spinner("Scan Turbo — executando", color=MAGENTA):
        while t1.is_alive() or t2.is_alive():
            time.sleep(0.12)

   
    if WHATWEB:
        try:
            ww_out = run_cmd(f"{WHATWEB} -q http://{host} --log-brief 2>/dev/null")
        except Exception:
            ww_out = ""

    techs = detectar_tecnologias(host, ".")
    return nmap_out, nikto_out, techs, ww_out

def scan_site_full(host):
    """
    Scan completo: nmap -sV, nikto completo e whatweb (se disponível).
    Retorna: nmap_out, nikto_out, techs, ww_out
    """
    ok("Iniciando scan FULL (pode demorar)...")
    nmap_out = run_cmd(f"{NMAP} -sV -n {host}")
    nikto_out = run_cmd(f"{NIKTO} -h {host}")
    ww_out = ""
    if WHATWEB:
        try:
            ww_out = run_cmd(f"{WHATWEB} -q http://{host}")
        except Exception:
            ww_out = ""
    techs = detectar_tecnologias(host, ".")
    return nmap_out, nikto_out, techs, ww_out

def scan_rede_turbo(alvo):
    """
    Scan rápido de rede.
    Retorna: nmap_out (string)
    """
    with Spinner("Scan de rede — executando", color=MAGENTA):
        return run_cmd(f"{NMAP} -T5 -F -n {alvo}")



def printed_menu():
    banner()
    print(f"{CYAN}Versão: {VERSION}{RESET}\n")
    print(f"{GREEN}1){RESET} Scan SITE (TURBO)")
    print(f"{GREEN}2){RESET} Scan SITE (FULL)")
    print(f"{GREEN}3){RESET} Scan REDE (TURBO)")
    print(f"{GREEN}4){RESET} Atualizar SaudadeDaEx")
    print(f"{GREEN}5){RESET} Desinstalar SaudadeDaEx")
    print(f"{GREEN}6){RESET} Sair\n")
    return input(f"{CYAN}Escolha: {RESET}")



def update_saudade():
    print(f"{CYAN}{BOLD}Verificando atualizações...{RESET}")

    INSTALL_PATH = "/usr/local/bin/saudade"
    RAW_URL = "https://raw.githubusercontent.com/Loki-dfs/SaudadeDaEX/main/saudadeDaEx.py"

    try:
        info("Baixando versão mais recente...")
        response = urllib.request.urlopen(RAW_URL, timeout=10)
        new_code = response.read().decode("utf-8")

        if len(new_code) < 100:
            err("Erro: código remoto parece inválido!")
            sys.exit()

        info(f"Atualizando arquivo em: {INSTALL_PATH}")
        with open(INSTALL_PATH, "w", encoding="utf-8") as f:
            f.write(new_code)
        os.chmod(INSTALL_PATH, 0o755)

        ok("SaudadeDaEx atualizado com sucesso!")
        info("Versão atualizada disponível agora com o comando: saudade")
    except Exception as e:
        err(f"Falha ao atualizar: {e}")

    sys.exit()

def uninstall_saudade():
    print(f"{RED}{BOLD}Iniciando desinstalação do SaudadeDaEx...{RESET}\n")

    INSTALL_PATH = "/usr/local/bin/saudade"

    if os.path.exists(INSTALL_PATH):
        try:
            os.remove(INSTALL_PATH)
            ok(f"Comando removido: {INSTALL_PATH}")
        except Exception:
            err(f"Não foi possível remover {INSTALL_PATH}")
    else:
        warn(f"O comando não estava instalado em {INSTALL_PATH}")

    removed = 0
    for pasta in os.listdir("."):
        if pasta.startswith("saudade_"):
            try:
                shutil.rmtree(pasta)
                removed += 1
            except Exception:
                pass

    ok(f"Pastas removidas: {removed}")

    HOME_CONFIG = os.path.expanduser("~/.saudade")
    if os.path.exists(HOME_CONFIG):
        try:
            shutil.rmtree(HOME_CONFIG)
            ok("Configurações removidas.")
        except Exception:
            err("Não foi possível remover configs.")

    ok("SaudadeDaEx removido do sistema.")
    sys.exit()


def main():
    deps = check_dependencies()
    if deps:
        err(f"Ferramentas faltando: {', '.join(deps)}")
        sys.exit()

    while True:
        choice = printed_menu()

        if choice == "4":
            update_saudade()
            continue
        if choice == "5":
            uninstall_saudade()
            continue
        if choice == "6":
            ok("Saindo…")
            sys.exit()

        if choice not in ("1", "2", "3"):
            err("Opção inválida.")
            time.sleep(1)
            continue

        confirm_auth()
        alvo = input(f"{CYAN}Digite o alvo:{RESET} ").strip()
        host = re.sub(r"^https?://", "", alvo).split("/")[0]

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pasta = f"saudade_{timestamp}"
        try:
            os.makedirs(pasta, exist_ok=True)
        except Exception as e:
            err(f"Falha ao criar pasta de relatório: {e}")
            continue

        ok(f"Pasta criada: {pasta}\n")

        nmap_out = ""
        nikto_out = ""
        techs = []
        ww_out = ""

        try:
            if choice == "1":
                info("Executando SITE TURBO…")
                nmap_out, nikto_out, techs, ww_out = scan_site_turbo(host)
            elif choice == "2":
                info("Executando SITE FULL…")
                nmap_out, nikto_out, techs, ww_out = scan_site_full(host)
            elif choice == "3":
                info("Executando REDE TURBO…")
                nmap_out = scan_rede_turbo(host)
                nikto_out = ""
                techs = []
                ww_out = ""
        except KeyboardInterrupt:
            warn("Scan interrompido pelo usuário.")
            continue
        except Exception as e:
            err(f"Erro durante o scan: {e}")
            continue

        try:
            with open(os.path.join(pasta, "nmap_raw.txt"), "w", encoding="utf-8") as f:
                f.write(nmap_out or "")
            if nikto_out:
                with open(os.path.join(pasta, "nikto_raw.txt"), "w", encoding="utf-8") as f:
                    f.write(nikto_out or "")
            if ww_out:
                with open(os.path.join(pasta, "whatweb_raw.txt"), "w", encoding="utf-8") as f:
                    f.write(ww_out or "")
            else:
                
                try:
                    url = "http://" + host if not re.match(r"^https?://", host) else host
                    req = urllib.request.Request(url, headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME})"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        headers = resp.headers
                        body = resp.read(100000).decode(errors="ignore")
                        with open(os.path.join(pasta, "tech_raw.txt"), "w", encoding="utf-8") as f:
                            f.write("=== HEADERS ===\n")
                            f.write(str(headers))
                            f.write("\n\n=== HTML (primeiros 100KB) ===\n")
                            f.write(body or "")
                except Exception:
                    pass
        except Exception as e:
            warn(f"Falha ao salvar saídas brutas: {e}")

        
        try:
            engine = InterpreterEngine(tool_name=TOOL_NAME)

            if choice in ("1", "2"):
                res = engine.interpret(
                    host,
                    nmap_out=nmap_out,
                    nikto_out=nikto_out,
                    whatweb_out=ww_out
                )
                interpreted_path = engine.generate_html_report(
                    pasta,
                    host,
                    portas_scored=res.get("ports", []),
                    nikto_scored=res.get("nikto", []),
                    techs=res.get("techs", [])
                )

                print(f"{GREEN}{BOLD}Resumo Interpretado:{RESET}")
                print(f"Risco global: {YELLOW}{res.get('risk', 'Desconhecido')}{RESET}")
                print(f"Tecnologias: {CYAN}{', '.join(res.get('techs', [])[:6]) or 'Nenhuma'}{RESET}")
                if res.get("recommendations"):
                    print(f"Recomendações automáticas: {MAGENTA}{len(res.get('recommendations'))}{RESET}")
                print()
                print(f"{YELLOW}Relatório interpretado salvo em:{RESET} {interpreted_path}\n")
            else:
                hosts, portas = interpretar_nmap_rede(nmap_out)
                ports_simple = []
                for p in portas:
                    try:
                        pn = int(p)
                    except Exception:
                        pn = 0
                    ports_simple.append({"port": pn, "proto": "tcp", "state": "open", "service": "unknown", "version": "", "risk": "Médio"})

                interpreted_path = engine.generate_html_report(
                    pasta,
                    host,
                    portas_scored=ports_simple,
                    nikto_scored=[],
                    techs=[]
                )

                print(f"{GREEN}{BOLD}Resumo Interpretado (REDE):{RESET}")
                print(f"Hosts ativos: {CYAN}{len(hosts)}{RESET}")
                print(f"Portas abertas (total): {MAGENTA}{len(portas)}{RESET}\n")
                print(f"{YELLOW}Relatório interpretado salvo em:{RESET} {interpreted_path}\n")

        except Exception as e:
            warn(f"Falha na interpretação (InterpreterEngine). O relatório bruto foi salvo. Erro: {e}")
            
            try:
                
                if choice in ("1", "2"):
                    vulns, caminhos = interpretar_nikto(nikto_out)
                    portas = interpretar_nmap_site(nmap_out)
                    resumo_path = gerar_html_resumo(pasta, host, "site", vulns=vulns, portas=portas, caminhos=caminhos, tecnologias=techs)
                else:
                    hosts, portas = interpretar_nmap_rede(nmap_out)
                    resumo_path = gerar_html_resumo(pasta, host, "rede", hosts=hosts, portas=portas, tecnologias=techs)
                if resumo_path:
                    info(f"Resumo simples gerado em: {resumo_path}")
            except Exception:
                pass

        if OPEN_FOLDER:
            if input(f"{CYAN}Abrir pasta agora? (y/n){RESET} ").lower() == "y":
                open_folder(pasta)

        if input(f"{CYAN}Rodar outro scan? (y/n){RESET} ").lower() != "y":
            ok("Saindo…")
            break

def check_dependencies():
    missing = []
    if shutil.which("nmap") is None:
        missing.append("nmap")
    if shutil.which("nikto") is None:
        missing.append("nikto")
    return missing


def print_help():
    print(f"""
{GREEN}{BOLD}SaudadeDaEx — Ajuda{RESET}

Comandos disponíveis:

  saudade                   → abre o menu  
  saudade --help            → mostra ajuda  
  saudade --version         → mostra a versão  
  saudade --update          → atualiza para a versão mais recente  
  saudade --uninstall       → remove completamente  
""")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()

        if arg in ("--help", "-h", "help"):
            print_help()
            sys.exit()

        if arg in ("--version", "-v"):
            print(f"{GREEN}{BOLD}SaudadeDaEx versão {VERSION}{RESET}")
            sys.exit()

        if arg in ("--update", "update"):
            update_saudade()

        if arg in ("--uninstall", "-u", "uninstall"):
            uninstall_saudade()

        print(f"{RED}Comando desconhecido: {arg}{RESET}")
        sys.exit()

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Interrompido pelo usuário.{RESET}")
        sys.exit()
