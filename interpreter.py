
import re
import datetime
import os
import html as html_lib
import json

class InterpreterEngine:
    """
    Interpreta saídas de nmap, nikto e whatweb e gera:
    - dict com dados estruturados
    - resumo humano em português
    - relatório HTML salvo no disco
    """

    
    HIGH_RISK_PORTS = {21,22,23,25,69,135,139,445,1433,1521,3306,3389}
    MEDIUM_RISK_PORTS = {80,443,8080,8443,8000,8888}

    def __init__(self, tool_name="saudadeDaEx"):
        self.tool_name = tool_name

    # ---------- parsers ----------
    def parse_nmap(self, nmap_out):
        """
        Retorna: portas = list of dicts {port:int, proto:'tcp', state, service, version}
                 hosts = list of ips
        """
        portas = []
        hosts = []
        if not nmap_out:
            return hosts, portas

        
        hosts += re.findall(r"Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", nmap_out)

        
        for m in re.finditer(r"(\d+)\/(tcp|udp)\s+(\w+)\s+([^\n\r]+)", nmap_out):
            port = int(m.group(1))
            proto = m.group(2)
            state = m.group(3)
            rest = m.group(4).strip()
            
            parts = rest.split(None,1)
            service = parts[0] if parts else ""
            version = parts[1] if len(parts)>1 else ""
            portas.append({
                "port": port,
                "proto": proto,
                "state": state,
                "service": service,
                "version": version
            })

        return hosts, portas

    def parse_nikto(self, nikto_out):
        """
        Retorna: findings = list of strings (achados)
        Heurística: linhas que começam com '+' ou contain 'OSVDB' etc.
        """
        findings = []
        if not nikto_out:
            return findings

        for line in nikto_out.splitlines():
            line = line.strip()
            if not line:
                continue
           
            if line.startswith("+") or "OSVDB-" in line or "ERROR" in line or "Uncommon header" in line:
               
                findings.append(re.sub(r"^\+\s*", "", line))
            else:
                
                if re.search(r"/[A-Za-z0-9_\-./]+", line) and ("200" in line or "Found" in line or "allowed" in line.lower()):
                    findings.append(line)
        return findings

    def parse_whatweb(self, whatweb_out):
        """
        Retorna lista de tecnologias (strings simples)
        WhatWeb output example: "http://host [200 OK] Engine: WordPress 5.8.0, jQuery"
        Heurística: extrair partes entre [ ] e após 'Engine:' e tokens comuns
        """
        techs = []
        if not whatweb_out:
            return techs

       
        for line in whatweb_out.splitlines():
            line = line.strip()
            if not line:
                continue
           
            m = re.search(r"Engine:\s*(.+)", line)
            if m:
                parts = [p.strip() for p in re.split(r",|\|", m.group(1)) if p.strip()]
                for p in parts:
                    if p not in techs:
                        techs.append(p)
            
            for kw in ["WordPress","Drupal","Joomla","php","nginx","Apache","IIS","Cloudflare","WAF","React","Angular","Vue","Express","Django","Flask"]:
                if re.search(re.escape(kw), line, re.IGNORECASE) and kw not in techs:
                    techs.append(kw)
        return techs

   
    def score_ports(self, portas):
        """
        Atribui severidade para portas: return list of portas with 'risk' field (Low/Medium/High)
        """
        scored = []
        for p in portas:
            portnum = p.get("port")
            risk = "Baixo"
            if portnum in self.HIGH_RISK_PORTS:
                risk = "Alto"
            elif portnum in self.MEDIUM_RISK_PORTS:
                risk = "Médio"
            else:
                
                if portnum < 1024:
                    risk = "Médio"
            p2 = dict(p)
            p2["risk"] = risk
            scored.append(p2)
        return scored

    def score_nikto(self, findings):
        """
        Classifica findings do Nikto por severidade simples:
        - linhas contendo 'server leaks' 'phpinfo' 'backup' 'config' -> Alto
        - 'X-Powered-By' 'cookie' -> Médio
        - outros -> Baixo
        """
        scored = []
        for f in findings:
            f_low = f.lower()
            sev = "Baixo"
            if any(x in f_low for x in ("phpinfo", "backup", ".env", "db_backup", "config", "password", "credentials", "traversal", "exposed")):
                sev = "Alto"
            elif any(x in f_low for x in ("x-powered-by","cookie","server","http methods", "allowed methods", "directory index", "index of")):
                sev = "Médio"
            scored.append({"finding": f, "risk": sev})
        return scored

    def aggregate_risk(self, portas_scored, nikto_scored):
        """
        Gera um risco global heurístico: Alto se qualquer item Alto, senão Médio se >=2 itens Medio, senão Baixo.
        """
        has_alto = any(p["risk"]=="Alto" for p in portas_scored) or any(n["risk"]=="Alto" for n in nikto_scored)
        if has_alto:
            return "Alto"
        count_medio = sum(1 for p in portas_scored if p["risk"]=="Médio") + sum(1 for n in nikto_scored if n["risk"]=="Médio")
        if count_medio >= 2:
            return "Médio"
        return "Baixo"

   
    def make_human_summary(self, host, portas_scored, nikto_scored, techs):
        """
        Retorna um par (titulo, texto) em português resumindo os achados de forma amigável.
        """
        total_vulns = sum(1 for n in nikto_scored if n["risk"]!="Baixo")
        portas_abertas = len(portas_scored)
        portas_altas = [p for p in portas_scored if p["risk"]=="Alto"]
        portas_medio = [p for p in portas_scored if p["risk"]=="Médio"]

        parts = []
        parts.append(f"Resumo rápido para <b>{html_lib.escape(host)}</b>:")

        parts.append(f"Foram identificadas <b>{portas_abertas}</b> portas abertas.")
        if portas_altas:
            parts.append(f"Portas de alto risco detectadas: {', '.join(str(p['port']) for p in portas_altas)}.")
        if portas_medio:
            parts.append(f"Portas de risco médio: {', '.join(str(p['port']) for p in portas_medio)}.")

        parts.append(f"Foram encontrados <b>{total_vulns}</b> achados importantes pelo Nikto (diretórios ou headers sensíveis).")

        if techs:
            parts.append(f"Tecnologias detectadas: {', '.join(html_lib.escape(t) for t in techs[:6])}.")

       
        agg = self.aggregate_risk(portas_scored, nikto_scored)
        if agg == "Alto":
            concl = "<b>Risco GLOBAL: Alto.</b> Recomenda-se ação imediata."
        elif agg == "Médio":
            concl = "<b>Risco GLOBAL: Médio.</b> Planeje correções em breve."
        else:
            concl = "<b>Risco GLOBAL: Baixo.</b> Monitorar e corrigir onde possível."
        parts.append(concl)

        return "<br>".join(parts)

    
    def recommendations(self, portas_scored, nikto_scored, techs):
        recs = []
       
        for p in portas_scored:
            if p["risk"]=="Alto":
                recs.append(f"Revisar serviço na porta {p['port']}. Feche se não for necessário ou restrinja por firewall.")
        
        for n in nikto_scored:
            f = n["finding"].lower()
            if "phpinfo" in f:
                recs.append("Remova qualquer phpinfo.php do servidor (contém informações sensíveis).")
            if ".env" in f or "backup" in f or ".git" in f:
                recs.append("Remova arquivos de backup e diretórios .git/.env acessíveis publicamente.")
            if "x-powered-by" in f:
                recs.append("Remova ou encubra o header X-Powered-By para reduzir fingerprinting.")
      
        if any("WordPress" in t for t in techs):
            recs.append("Verifique plugins e atualize o WordPress e seus plugins para a versão mais recente.")
       
        seen = []
        out = []
        for r in recs:
            if r not in seen:
                seen.append(r)
                out.append(r)
        return out[:8]

    
    def generate_html_report(self, pasta, host, portas_scored, nikto_scored, techs, save_name=None):
        timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        if not save_name:
            save_name = f"{re.sub(r'[^A-Za-z0-9_.-]','_',host)}_interpreted.html"
        path = os.path.join(pasta, save_name)

       
        summary = self.make_human_summary(host, portas_scored, nikto_scored, techs)
        recs = self.recommendations(portas_scored, nikto_scored, techs)

        portas_html = "".join(
            f"<tr><td>{p['port']}/{p['proto']}</td><td>{html_lib.escape(p.get('service',''))}</td><td>{html_lib.escape(p.get('version',''))}</td><td>{p['state']}</td><td>{p['risk']}</td></tr>"
            for p in portas_scored
        )

        nikto_html = "".join(f"<li><code>{html_lib.escape(n['finding'])}</code> — <b>{n['risk']}</b></li>" for n in nikto_scored)
        tech_html = "".join(f"<li>{html_lib.escape(t)}</li>" for t in techs)

        recs_html = "".join(f"<li>{html_lib.escape(r)}</li>" for r in recs)

        html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Relatório — {html_lib.escape(host)}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;background:#f7f7f7;padding:20px;color:#111}}
.container{{max-width:980px;margin:0 auto}}
.card{{background:#fff;padding:18px;border-radius:12px;box-shadow:0 8px 20px rgba(0,0,0,0.06);margin-bottom:18px}}
h1{{margin:0 0 8px 0}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #eee}}
.badge{{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:700}}
.high{{background:#ffe7e7;color:#a00}}
.med{{background:#fff4d6;color:#b36c00}}
.low{{background:#e8fff0;color:#0a7a3a}}
</style>
</head><body>
<div class="container">
  <div class="card">
    <h1>Relatório Interpretado — {html_lib.escape(host)}</h1>
    <small>Gerado por {html_lib.escape(self.tool_name)} em {timestamp}</small>
    <div style="margin-top:12px">{summary}</div>
  </div>

  <div class="card">
    <h2>Portas detectadas</h2>
    <table>
      <thead><tr><th>Porta</th><th>Serviço</th><th>Versão</th><th>Estado</th><th>Risco</th></tr></thead>
      <tbody>{portas_html}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Achados do Nikto</h2>
    <ul>{nikto_html or "<li>Nenhum achado relevante</li>"}</ul>
  </div>

  <div class="card">
    <h2>Tecnologias detectadas</h2>
    <ul>{tech_html or "<li>Nenhuma tecnologia detectada</li>"}</ul>
  </div>

  <div class="card">
    <h2>Recomendações</h2>
    <ol>{recs_html or "<li>Sem recomendações automáticas</li>"}</ol>
  </div>
</div>
</body></html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    
    def interpret(self, host, nmap_out="", nikto_out="", whatweb_out=""):
        """
        Fluxo único: parse -> score -> summary -> recomendações -> HTML
        Retorna dicionário com tudo e caminho do HTML.
        """
        hosts, portas = self.parse_nmap(nmap_out)
        nikto_findings = self.parse_nikto(nikto_out)
        techs = self.parse_whatweb(whatweb_out)

        portas_scored = self.score_ports(portas)
        nikto_scored = self.score_nikto(nikto_findings)

        agg = self.aggregate_risk(portas_scored, nikto_scored)
        summary_html = self.make_human_summary(host, portas_scored, nikto_scored, techs)
        recs = self.recommendations(portas_scored, nikto_scored, techs)

        result = {
            "host": host,
            "hosts_found_by_nmap": hosts,
            "ports": portas_scored,
            "nikto": nikto_scored,
            "techs": techs,
            "risk": agg,
            "summary_html": summary_html,
            "recommendations": recs,
            "generated_at": datetime.datetime.now().isoformat()
        }

       
        return result
