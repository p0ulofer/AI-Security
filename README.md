# AI Network Threat Detection System

Sistema local de detecção de ameaças de rede que captura tráfego em tempo real utilizando Scapy, aplica regras heurísticas customizáveis e utiliza um LLM local (via Ollama) para classificar e pontuar eventos suspeitos.

---

## Visão Geral

O sistema monitora continuamente o tráfego de rede e as conexões ativas. Quando padrões suspeitos são detectados por regras heurísticas (ex.: varredura de portas ou SYN flood), um resumo estruturado é enviado a um modelo de linguagem local (Mistral 7B via Ollama) que classifica a ameaça, atribui um score de severidade (1–10) e gera uma explicação em português. Os alertas são salvos em um banco SQLite e exibidos em um dashboard web.

```
tráfego de rede ──► LivePacketCollector ──► Preprocessor ──► [heurísticas?] ──► Ollama LLM
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
pip install requests psutil scapy
```

> **Nota:** Como o Scapy captura pacotes diretamente da interface de rede, é necessário executar o script principal com privilégios de superusuário (`sudo`).

---

## Estrutura de Arquivos

```
ai-analysis/
├── collector_live.py   # Captura pacotes em tempo real e conexões de rede
├── preprocessor.py     # Agrega eventos em janelas e aplica heurísticas parametrizáveis
├── ollama_client.py    # Integração com a API REST do Ollama
├── alerter.py          # Salva alertas no SQLite e exibe no terminal com cores
├── main.py             # Orquestrador principal do sistema (captura em tempo real)
├── dashboard.py        # Servidor web leve para visualizar os alertas
├── test_ollama.py      # Verifica a conectividade com o Ollama
└── threats.db          # Banco SQLite gerado automaticamente na primeira execução
```

---

## Heurísticas Suportadas

O pré-processador monitora e aplica as seguintes regras heurísticas sobre o tráfego capturado:
1. **Varredura de Portas (Port Scan):** Um mesmo IP de origem acessando mais de `port-scan-threshold` portas diferentes em 30 segundos.
2. **SYN Flood:** Um mesmo IP de origem enviando mais de `syn-flood-threshold` pacotes TCP SYN em 30 segundos.
3. **Volume Anômalo:** Um mesmo IP de origem enviando mais de `volume-mb-threshold` MB em 30 segundos.
4. **Portas Sensíveis:** Qualquer tentativa de acesso a portas críticas pré-definidas (ex.: `22`, `23`, `3389`, `445`, `1433`).

---

## Argumentos do Orquestrador (`main.py`)

O script `main.py` aceita os seguintes parâmetros de linha de comando:

| Argumento | Padrão | Descrição |
|---|---|---|
| `--window` | `30` | Tamanho da janela de agregação em segundos |
| `--conn-interval` | `5` | Intervalo de snapshot de conexões em segundos |
| `--db` | `threats.db` | Caminho do banco SQLite |
| `--model` | `mistral:7b-instruct-q4_K_M` | Modelo Ollama a usar |
| `--url` | `http://localhost:11434` | URL base da API Ollama |
| `--iface` | `None` | Interface de rede a monitorar (detecta automaticamente se omitido) |
| `--ssh-fail-threshold` | `5` | Falhas de login SSH para disparar alerta |
| `--conn-spike-threshold` | `10` | Conexões do mesmo IP para disparar alerta |
| `--port-scan-threshold` | `10` | Portas diferentes para detectar port scan |
| `--syn-flood-threshold` | `50` | Pacotes SYN para detectar SYN flood |
| `--volume-mb-threshold` | `5.0` | Volume em MB para detectar exfiltração |

---

## Como Executar

### 1. Verificar o Ollama

```bash
python3 test_ollama.py
```

### 2. Iniciar o detector de ameaças em tempo real

```bash
sudo python3 main.py --window 30 --db threats.db --port-scan-threshold 10
```

### 3. Abrir o dashboard web

```bash
python3 dashboard.py --db threats.db --port 8080
```

Acesse no navegador: **http://localhost:8080**
