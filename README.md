# AI Network Threat Detection System

Sistema local de detecção de ameaças de rede que combina monitoramento de logs em tempo real, heurísticas simples e um LLM local (via Ollama) para classificar e pontuar eventos suspeitos.

---

## Visão Geral

O sistema monitora continuamente os logs do sistema operacional e as conexões de rede ativas. Quando padrões suspeitos são detectados por regras simples (ex.: múltiplas falhas de login), um resumo estruturado é enviado a um modelo de linguagem local (Mistral 7B via Ollama) que classifica a ameaça, atribui um score de severidade (1–10) e gera uma explicação. Os alertas são salvos em banco SQLite e exibidos em um dashboard web.
 .
```
logs + conexões ──► Collector ──► Preprocessor ──► [regras?] ──► Ollama LLM
                                                          │               │
                                                     (ignora)        Alerter
                                                                    /       \
                                                              SQLite     Terminal
                                                                 │
                                                           Dashboard Web
```

---

## Ambiente Necessário

| Componente | Versão |
|---|---|
| Sistema Operacional | WSL2 Ubuntu 24.04 |
| Python | 3.10+ |
| GPU | NVIDIA RTX 3050 6 GB VRAM (ou superior) |
| Ollama | Rodando em `http://localhost:11434` |
| Modelo | `mistral:7b-instruct-q4_K_M` |

### Dependências Python

```bash
pip install requests psutil
```

> `sqlite3`, `http.server`, `argparse`, `threading` e `queue` fazem parte da stdlib e não precisam ser instalados.

---

## Estrutura de Arquivos

```
ai-analysis/
├── collector.py        # Lê logs em tempo real e coleta conexões de rede
├── preprocessor.py     # Agrega eventos em janelas de 30 s e aplica heurísticas
├── ollama_client.py    # Integração com a API REST do Ollama
├── alerter.py          # Salva alertas no SQLite e exibe no terminal com cores
├── main.py             # Orquestrador principal do sistema
├── dashboard.py        # Servidor web leve para visualizar os alertas
├── simulate_attack.py  # Gerador de eventos de ataque para testes
├── test_ollama.py      # Verifica a conectividade com o Ollama
└── threats.db          # Banco SQLite gerado automaticamente na primeira execução
```

---

## Módulos

### `collector.py` — Coletor de Eventos
- Faz *tail* em tempo real dos arquivos de log configurados (ex.: `/var/log/auth.log`, `/var/log/syslog`) usando threads separadas por arquivo.
- Monitora conexões de rede ativas via `psutil.net_connections()`.
- Utiliza uma fila thread-safe (`queue.Queue`) para passar eventos ao preprocessador.

### `preprocessor.py` — Pré-processador e Motor de Regras
- Agrega logs e snapshots de conexões em **janelas de 30 segundos**.
- Aplica heurísticas simples sem chamar o LLM:
  - **Brute force SSH**: mais de N falhas de login do mesmo IP.
  - **Escalação de privilégios**: sessão aberta para o usuário root.
  - **Port scan**: um mesmo IP conectando a muitas portas diferentes.
  - **Spike de conexões**: IP com volume anormal de conexões.
  - **Falhas de sistema**: segfaults, core dumps, erros de kernel.
- Se nenhuma regra for acionada, o LLM **não é chamado** (economia de GPU).
- Se alguma regra for acionada, gera um resumo estruturado em texto para envio ao LLM.

### `ollama_client.py` — Integração com o LLM
- Envia o resumo de eventos para `POST /api/generate` da API do Ollama.
- Usa um prompt de sistema focado em segurança que exige resposta em JSON:
  ```json
  { 
    "classification": "Brute Force SSH",
    "score": 8,
    "explanation": "Múltiplas tentativas de login falhas do mesmo IP."
  }
  ```
- Timeout configurável (padrão: 60 s) para não bloquear o loop principal.

### `alerter.py` — Sistema de Alertas
- Cria e gerencia o banco `threats.db` com a tabela `alerts`:
  ```sql
  CREATE TABLE alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT,
      threat_type TEXT,
      severity_score INTEGER,
      explanation TEXT,
      details TEXT
  );
  ```
- Exibe alertas no terminal com **cores ANSI** por nível de severidade:

  | Score | Cor | Nível |
  |---|---|---|
  | 7 – 10 | 🔴 Vermelho | CRITICAL |
  | 4 – 6 | 🟡 Amarelo | WARNING |
  | 1 – 3 | 🟢 Verde | INFO |

### `main.py` — Orquestrador Principal
Loop principal que integra todos os módulos:

```
Collector → fila de eventos → Preprocessor (janela 30 s)
                                     │
                              regras acionadas?
                             /                \
                           NÃO               SIM
                        (descarta)     Ollama LLM → Alerter
```

**Opções de linha de comando:**

| Argumento | Padrão | Descrição |
|---|---|---|
| `--logs` | `/var/log/auth.log,/var/log/syslog` | Arquivos de log separados por vírgula |
| `--window` | `30` | Tamanho da janela de agregação em segundos |
| `--conn-interval` | `5` | Intervalo de snapshot de conexões em segundos |
| `--db` | `threats.db` | Caminho do banco SQLite |
| `--model` | `mistral:7b-instruct-q4_K_M` | Modelo Ollama a usar |
| `--url` | `http://localhost:11434` | URL base da API Ollama |

### `dashboard.py` — Dashboard Web
- Servidor HTTP leve usando apenas `http.server` da stdlib (sem Flask).
- Escuta em `0.0.0.0` para ser acessível do Windows via WSL2.
- Interface web com:
  - **Tabela de alertas** com colunas: timestamp, tipo, score, explicação.
  - **Borda colorida** por severidade (vermelho, laranja, verde).
  - **Badge** de score destacado visualmente.
  - **Contadores** no topo: total, críticos (≥ 8), alertas de hoje.
  - **Filtro** por nível de severidade.
  - **Auto-refresh** a cada 10 segundos.
  - Layout escuro com fonte monospace estilo terminal.

---

## Como Executar

### 1. Verificar o Ollama

```bash
python3 test_ollama.py
```

### 2. Iniciar o detector (modo produção com logs reais)

```bash
sudo python3 main.py \
    --logs /var/log/auth.log,/var/log/syslog \
    --window 30 \
    --db threats.db
```

> ⚠️ `sudo` pode ser necessário para ler `/var/log/auth.log`.

### 3. Iniciar o detector (modo teste com logs simulados)

```bash
# Terminal 1 — inicia o detector
python3 main.py --logs mock_auth.log,mock_syslog --window 15

# Terminal 2 — injeta eventos de ataque simulados
python3 simulate_attack.py
```

### 4. Abrir o dashboard web

```bash
python3 dashboard.py --db threats.db --port 8080
```

Acesse no navegador: **http://localhost:8080**

---

## Fluxo de um Evento de Ataque (Exemplo)

1. O atacante tenta fazer brute force no SSH: 6 tentativas de login em 10 segundos.
2. O `collector.py` captura as linhas `Failed password for ...` do `auth.log`.
3. O `preprocessor.py` ao final da janela detecta: **6 falhas do mesmo IP** → regra acionada.
4. O `ollama_client.py` envia o resumo ao Mistral e recebe:
   ```json
   { "classification": "Brute Force SSH", "score": 7, "explanation": "..." }
   ```
5. O `alerter.py` salva no SQLite e imprime no terminal em **vermelho**.
6. O `dashboard.py` exibe o alerta na tabela web na próxima atualização (≤ 10 s).

---
