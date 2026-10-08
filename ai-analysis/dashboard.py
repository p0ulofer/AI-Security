#!/usr/bin/env python3
# --------------------------------------------------------------
# dashboard.py
#   Lightweight security‑alert dashboard (stdlib only)
#   Usage: python3 dashboard.py --db threats.db --port 8080
# --------------------------------------------------------------
import argparse
import json
import sqlite3
import datetime as dt
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
# ----------------------------------------------------------------------
# HTML / CSS / JavaScript (embedded as a Python triple‑quoted string)
# ----------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Threat Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    :root{
        --bg:#0d0d0d;
        --fg:#e0e0e0;
        --red:#ff4c4c;
        --orange:#ffae42;
        --green:#4caf50;
        --card:#1a1a1a;
        --header:#111;
    }
    body{
        background:var(--bg);
        color:var(--fg);
        font-family:"Courier New",Courier,monospace;
        margin:0;
        display:flex;
        flex-direction:column;
        min-height:100vh;
    }
    header{
        background:var(--header);
        padding:1rem;
        text-align:center;
        font-size:1.5rem;
        color:#fff;
    }
    #stats{
        display:flex;
        justify-content:center;
        gap:2rem;
        margin:1rem 0;
        font-size:0.95rem;
    }
    #stats span{
        background:var(--card);
        padding:0.4rem 0.8rem;
        border-radius:4px;
    }
    #filter{
        margin:0 auto 1rem auto;
        display:flex;
        align-items:center;
        gap:0.5rem;
        color:#ddd;
    }
    select{
        background:var(--card);
        color:var(--fg);
        border:none;
        padding:0.3rem 0.6rem;
        border-radius:4px;
    }
    table{
        width:90%;
        margin:0 auto 2rem auto;
        border-collapse:collapse;
        table-layout:auto;
    }
    th, td{
        padding:0.6rem 0.8rem;
        text-align:left;
    }
    thead{
        background:var(--card);
        position:sticky;
        top:0;
        z-index:1;
    }
    tbody tr{
        background:var(--bg);
        transition:background 0.2s ease;
        border-left:3px solid transparent;
    }
    tbody tr:hover{
        background:rgba(255,255,255,0.05);
    }
    /* colored left-border accent per severity – row stays black */
    tr.score-1-4  { border-left-color:var(--green); }
    tr.score-5-7  { border-left-color:var(--orange); }
    tr.score-8-10 { border-left-color:var(--red); }
    .badge{
        display:inline-block;
        padding:0.2rem 0.5rem;
        border-radius:4px;
        font-weight:bold;
        color:#fff;
    }
    /* badge fill colors stay as before */
    .badge.score-1-4  { background:var(--green); }
    .badge.score-5-7  { background:var(--orange); }
    .badge.score-8-10 { background:var(--red); }
</style>
</head>
<body>
<header>Threat Intelligence Dashboard</header>
<div id="stats">
    <span id="total">Total: 0</span>
    <span id="critical">Críticos (≥8): 0</span>
    <span id="today">Hoje: 0</span>
</div>
<div id="filter">
    <label for="sev">Filtro de severidade:</label>
    <select id="sev">
        <option value="all">Todos</option>
        <option value="critical">Crítico (≥8)</option>
        <option value="medium">Médio (5‑7)</option>
        <option value="low">Baixo (1‑4)</option>
    </select>
</div>
<table>
    <thead>
        <tr>
            <th>Timestamp</th>
            <th>Tipo de ameaça</th>
            <th>Score</th>
            <th>Explicação</th>
        </tr>
    </thead>
    <tbody id="tbl-body"></tbody>
</table>
<script>
const tblBody = document.getElementById('tbl-body');
const totalSpan   = document.getElementById('total');
const critSpan    = document.getElementById('critical');
const todaySpan   = document.getElementById('today');
const filterSel   = document.getElementById('sev');
function colourClass(score){
    if(score>=8) return 'score-8-10';
    if(score>=5) return 'score-5-7';
    return 'score-1-4';
}
function matchesFilter(score){
    const v = filterSel.value;
    if(v==='all') return true;
    if(v==='critical') return score>=8;
    if(v==='medium')   return score>=5 && score<8;
    if(v==='low')      return score<5;
    return true;
}
async function loadData(){
    const resp = await fetch('/alerts');
    const data = await resp.json();   // lista de dicts
    tblBody.innerHTML='';
    let total=0, crit=0, today=0;
    const todayStr = new Date().toISOString().slice(0,10);
    data.forEach(rec=>{
        const score = rec.severity_score;
        if(!matchesFilter(score)) return;
        total++;
        if(score>=8) crit++;
        if(rec.timestamp.slice(0,10)===todayStr) today++;
        const tr = document.createElement('tr');
        tr.className = colourClass(score);
        tr.innerHTML = `
            <td>${rec.timestamp}</td>
            <td>${rec.threat_type}</td>
            <td><span class="badge ${colourClass(score)}">${score}</span></td>
            <td>${rec.explanation}</td>
        `;
        tblBody.appendChild(tr);
    });
    totalSpan.textContent   = `Total: ${total}`;
    critSpan.textContent    = `Críticos (≥8): ${crit}`;
    todaySpan.textContent   = `Hoje: ${today}`;
}
// refresh every 10 s
loadData();
setInterval(loadData,10000);
filterSel.addEventListener('change',loadData);
</script>
</body>
</html>
"""
# ----------------------------------------------------------------------
# Helper – fetch alerts from SQLite and return JSON serialisable list
# ----------------------------------------------------------------------
def fetch_alerts(db_path):
    """Return a list of dicts ordered by newest first."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(
        """SELECT id,
                  timestamp,
                  threat_type,
                  severity_score,
                  explanation,
                  details
           FROM alerts
           ORDER BY timestamp DESC"""
    )
    rows = cur.fetchall()
    con.close()
    # Convert Row objects to plain dicts (JSON friendly)
    return [dict(r) for r in rows]
# ----------------------------------------------------------------------
# HTTP request handler
# ----------------------------------------------------------------------
class DashboardHandler(BaseHTTPRequestHandler):
    # we keep the DB path as a class attribute set at start‑up
    db_path = None
    def _set_headers(self, content_type="text/html"):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._set_headers("text/html")
            self.wfile.write(PAGE.encode("utf-8"))
        elif path == "/alerts":
            # JSON endpoint used by the JS front‑end
            alerts = fetch_alerts(self.db_path)
            self._set_headers("application/json")
            self.wfile.write(json.dumps(alerts, ensure_ascii=False).encode("utf-8"))
        elif path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    # Suppress noisy logging (optional)
    def log_message(self, fmt, *args):
        return  # comment this line to enable request logs
# ----------------------------------------------------------------------
# Argument parsing & server start‑up
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Simple security‑alert dashboard (stdlib only)"
    )
    parser.add_argument(
        "--db",
        required=True,
        help="Path to SQLite database (e.g. threats.db)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    args = parser.parse_args()
    # bind to 0.0.0.0 so Windows can reach it via WSL2
    server_address = ("0.0.0.0", args.port)
    DashboardHandler.db_path = args.db
    httpd = HTTPServer(server_address, DashboardHandler)
    print(f"\n🚀 Dashboard rodando em http://0.0.0.0:{args.port}")
    print(f"🔎 Usando banco SQLite: {args.db}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Servidor interrompido pelo usuário.")
    finally:
        httpd.server_close()
if __name__ == "__main__":
    main()
