# AI Network Threat Detection System

Sistema local de detecção de ameaças de rede que captura tráfego em tempo real utilizando Scapy, aplica regras heurísticas customizáveis, roda em paralelo um classificador XGBoost sobre cada IP monitorado e utiliza um LLM local (via Ollama) para classificar e pontuar eventos suspeitos.

---

## Visão Geral

O sistema monitora continuamente o tráfego de rede e as conexões ativas. A cada janela, dois sinais são avaliados em paralelo:

1. **Heurísticas** — regras customizáveis no pré-processador (ex.: varredura de portas ou SYN flood).
2. **XGBoost** — um classificador treinado que atribui uma probabilidade de ataque (0–1) por IP.

O módulo `combiner.py` une os dois sinais num veredito único: se a heurística disparou **ou** algum IP ultrapassou o threshold do XGBoost, um resumo estruturado é enviado a um modelo de linguagem local (Qwen 2.5 3B via Ollama) que classifica a ameaça, atribui um score de severidade (1–10) e gera uma explicação em português. Os alertas são salvos em um banco SQLite e exibidos em um dashboard web.

```
                                          ┌─► heurísticas (preprocessor) ──────┐
tráfego de rede ──► LivePacketCollector ──┤                                    ├──► combiner ──► [alerta?] ──► Ollama LLM ──► Alerter
                                          └─► features ──► XGBoost (0-1) ──────┘                       │               │
                                                                                                   (ignora)      SQLite + Terminal
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
| Modelo | `qwen2.5:3b-instruct-q4_K_M` |

### Dependências Python

```bash
pip install requests psutil scapy
```

Para o classificador XGBoost e os scripts de treino:

```bash
pip install xgboost scikit-learn pandas numpy matplotlib
```

> **Nota:** Como o Scapy captura pacotes diretamente da interface de rede, é necessário executar o script principal com privilégios de superusuário (`sudo`).

---

## Estrutura de Arquivos

```
ai-analysis/
├── training/
│   ├── gerar_dataset_treino.py   # Captura tráfego real e gera training/dataset_real.csv
│   ├── treinar_xgboost_ids.py    # Treina o XGBoost usando o FEATURE_SCHEMA
│   ├── dataset_real.csv          # Dataset de treino (gerado pelo script acima)
│   └── datasets/                 # CICIDS2017 (dataset legado, usado só como referência)
├── models/
│   └── xgboost_ids_model.json    # Modelo XGBoost carregado em tempo real
├── feature_extractor.py          # Monta as features por IP a partir dos trackers do preprocessor
├── classifier.py                 # ThreatClassifier: score de probabilidade de ataque (0-1) por IP
├── combiner.py                   # Combina heurísticas + XGBoost num veredito único
├── collector_live.py             # Captura pacotes em tempo real e conexões de rede
├── preprocessor.py               # Agrega eventos em janelas e aplica heurísticas parametrizáveis
├── ollama_client.py              # Integração com a API REST do Ollama
├── alerter.py                    # Salva alertas no SQLite e exibe no terminal com cores
├── main.py                       # Orquestrador principal do sistema (captura em tempo real)
├── dashboard.py                  # Servidor web leve para visualizar os alertas
├── test_combiner.py              # Teste do combinador de sinais (sem framework)
├── test_ollama.py                # Verifica a conectividade com o Ollama
└── threats.db                    # Banco SQLite gerado automaticamente na primeira execução
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
| `--model` | `qwen2.5:3b-instruct-q4_K_M` | Modelo Ollama a usar |
| `--url` | `http://localhost:11434` | URL base da API Ollama |
| `--iface` | `None` | Interface de rede a monitorar (detecta automaticamente se omitido) |
| `--ssh-fail-threshold` | `5` | Falhas de login SSH para disparar alerta |
| `--conn-spike-threshold` | `10` | Conexões do mesmo IP para disparar alerta |
| `--port-scan-threshold` | `10` | Portas diferentes para detectar port scan |
| `--syn-flood-threshold` | `50` | Pacotes SYN para detectar SYN flood |
| `--volume-mb-threshold` | `5.0` | Volume em MB para detectar exfiltração |
| `--xgboost-model` | `models/xgboost_ids_model.json` | Caminho do modelo XGBoost treinado |
| `--xgboost-threshold` | `0.7` | Probabilidade mínima do XGBoost para alertar |
| `--disable-ml` | desativado | Desativa o XGBoost (modo somente heurísticas) |

---

## Modelo Híbrido (Heurísticas + XGBoost)

As heurísticas continuam rodando exatamente como sempre rodaram — nenhuma regra foi removida ou enfraquecida. Em paralelo, o `feature_extractor.py` lê os trackers do pré-processador (deques de 30s por IP) e monta um vetor de features com o esquema `FEATURE_SCHEMA`:

`portas_distintas_30s`, `pacotes_syn_30s`, `volume_bytes_30s`, `conexoes_30s`, `falhas_login_30s`, `acessos_porta_sensivel`

O `classifier.py` devolve a probabilidade de ataque (0–1) de cada IP e o `combiner.py` decide o veredito final: **alerta se a heurística disparou OU se algum IP passou de `--xgboost-threshold`**, combinando ainda a severidade dos dois sinais (base pelas regras + bônus proporcional ao score do XGBoost, capada em 10). Os sinais do XGBoost entram no resumo enviado ao LLM.

Se o modelo não existir, estiver corrompido ou não corresponder ao `FEATURE_SCHEMA`, o sistema avisa no log e continua operando apenas com as heurísticas (score do XGBoost = 0.0). Use `--disable-ml` para forçar o modo somente heurísticas.

### Sobre o modelo distribuído inicialmente

O arquivo `models/xgboost_ids_model.json` que vem com o repositório foi treinado no dataset **CICIDS2017** e serve apenas como **ponto de partida para validar o pipeline** (captura → features → classificador → combiner → LLM). Como ele espera as 68 colunas de fluxo do CICIDS2017 e não as 6 features do `FEATURE_SCHEMA`, ele gera score 0.0 em tempo real até ser retreinado.

**O modelo recomendado para uso real é o retreinado sobre o tráfego real do ambiente:**

```bash
cd ai-analysis/training

# 1. Gere o dataset a partir do tráfego real (rótulo pelas heurísticas, por padrão)
sudo python3 gerar_dataset_treino.py --duration 300

# ... ou monte rótulos manualmente em execuções separadas e acumule com --append:
sudo python3 gerar_dataset_treino.py --rotulo normal --duration 120 --append
sudo python3 gerar_dataset_treino.py --rotulo ataque --duration 60 --append

# 2. Treine o modelo (salva em ../models/xgboost_ids_model.json)
python3 treinar_xgboost_ids.py
```

O treino importa o `FEATURE_SCHEMA` do `feature_extractor.py`, garantindo ordem idêntica de colunas entre treino e inferência.


---

## Como Executar

Todos os comandos abaixo rodam de dentro da pasta `ai-analysis/`:

```bash
cd ai-analysis
```

### 1. Verificar o Ollama

```bash
python3 test_ollama.py
```

### 2. Iniciar o detector de ameaças em tempo real

```bash
sudo python3 main.py --window 30 --db threats.db --port-scan-threshold 10
```

Com o classificador XGBoost habilitado (padrão):

```bash
sudo python3 main.py --xgboost-model models/xgboost_ids_model.json --xgboost-threshold 0.7
```

Somente heurísticas (sem ML):

```bash
sudo python3 main.py --disable-ml
```

### 3. Abrir o dashboard web

```bash
python3 dashboard.py --db threats.db --port 8080
```

Acesse no navegador: **http://localhost:8080**

### 4. Rodar os testes

```bash
python3 test_combiner.py
```
