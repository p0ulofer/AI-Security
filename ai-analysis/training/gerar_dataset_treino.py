"""
Gera o dataset de treino (training/dataset_real.csv) a partir do tráfego real.

Roda o sistema de captura por um tempo, aplica extract_features_by_ip em cada
janela e rotula cada linha (IP x janela) como normal (0) ou ataque (1),
produzindo um CSV no formato exato do FEATURE_SCHEMA + coluna "label".

Modos de rótulo (--rotulo):
  - heuristica (padrão): usa as próprias regras do preprocessor como rótulo
    inicial da janela (1 se alguma regra disparou, senão 0)
  - normal: toda janela rotulada como normal (capture uma baseline limpa)
  - ataque:  toda janela rotulada como ataque (simule um ataque durante a captura)

Como usar (rode a partir de training/, com sudo para capturar pacotes):
    1. Baseline de tráfego limpo:
       sudo python3 gerar_dataset_treino.py --rotulo normal --duration 120 --append
    2. Tráfego com ataque simulado (port scan, etc.):
       sudo python3 gerar_dataset_treino.py --rotulo ataque --duration 60 --append
    3. Ou deixe as heurísticas rotularem sozinhas:
       sudo python3 gerar_dataset_treino.py --rotulo heuristica --duration 300

Obs.: o rótulo é por janela (nível da janela inteira). Após montar o dataset,
vale revisar manualmente as linhas se quiser rótulos mais granulares por IP.
"""

import argparse
import csv
import os
import sys
import time

# Permite importar os módulos de ../ (pai deste script) — feature_extractor etc.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector_live import LivePacketCollector
from preprocessor import EventPreprocessor
from feature_extractor import FEATURE_SCHEMA, extract_features_by_ip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PADRAO = os.path.join(BASE_DIR, "dataset_real.csv")


def main():
    parser = argparse.ArgumentParser(
        description="Gera dataset de treino (FEATURE_SCHEMA + label) a partir do tráfego real"
    )
    parser.add_argument("--duration", type=int, default=300,
                        help="Duração da captura em segundos (default: 300)")
    parser.add_argument("--window", type=int, default=30,
                        help="Tamanho da janela de agregação em segundos (default: 30)")
    parser.add_argument("--conn-interval", type=int, default=5,
                        help="Intervalo de snapshot de conexões em segundos (default: 5)")
    parser.add_argument("--iface", type=str, default=None,
                        help="Interface de rede a monitorar (detecta automaticamente se omitido)")
    parser.add_argument("--rotulo", choices=["heuristica", "normal", "ataque"],
                        default="heuristica",
                        help="Como rotular cada janela (default: heuristica)")
    parser.add_argument("--out", type=str, default=DATASET_PADRAO,
                        help=f"Caminho do CSV de saída (default: {DATASET_PADRAO})")
    parser.add_argument("--append", action="store_true",
                        help="Acrescenta ao CSV existente em vez de sobrescrever")
    args = parser.parse_args()

    # Mesmos thresholds das heurísticas do main.py
    preprocessor = EventPreprocessor()
    collector = LivePacketCollector(iface=args.iface)

    print("Iniciando captura de pacotes em tempo real...")
    collector.start()

    linhas = []
    total_janelas = 0
    janelas_suspeitas = 0
    start_time = time.time()
    last_window_time = start_time
    last_conn_time = start_time

    try:
        while time.time() - start_time < args.duration:
            current_time = time.time()

            # 1. Novos eventos de log/pacotes
            for log in collector.get_new_events():
                if log.get("type") == "error":
                    print(f"\n[ERRO FATAL] {log.get('content')}")
                    print("Execute com privilégios elevados: sudo python3 gerar_dataset_treino.py")
                    sys.exit(1)
                preprocessor.add_log(log)

            # 2. Snapshot periódico de conexões
            if current_time - last_conn_time >= args.conn_interval:
                preprocessor.add_connections_snapshot(collector.get_active_connections())
                last_conn_time = current_time

            # 3. Fim da janela: extrai features e rotula
            if current_time - last_window_time >= args.window:
                is_suspicious, rules, _ = preprocessor.process_window()

                if args.rotulo == "heuristica":
                    rotulo = 1 if is_suspicious else 0
                elif args.rotulo == "normal":
                    rotulo = 0
                else:
                    rotulo = 1

                features_by_ip = extract_features_by_ip(preprocessor, current_time)
                for ip, features in features_by_ip.items():
                    linhas.append([features[c] for c in FEATURE_SCHEMA] + [rotulo])

                total_janelas += 1
                if is_suspicious:
                    janelas_suspeitas += 1
                decorrido = int(current_time - start_time)
                print(f"  [{decorrido}s] Janela {total_janelas}: {len(features_by_ip)} IPs, "
                      f"rótulo={rotulo}"
                      + (f" (regras: {len(rules)})" if rules else ""))

                preprocessor.clear()
                last_window_time = current_time

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuário.")
    finally:
        collector.stop()

    if not linhas:
        print("Nenhuma feature extraída — dataset não gerado.")
        return

    # Escreve o CSV no formato do FEATURE_SCHEMA + label
    modo = "a" if args.append and os.path.exists(args.out) else "w"
    escrever_cabecalho = modo == "w"
    with open(args.out, modo, newline="") as f:
        writer = csv.writer(f)
        if escrever_cabecalho:
            writer.writerow(list(FEATURE_SCHEMA) + ["label"])
        writer.writerows(linhas)

    print(f"\nDataset salvo em {args.out}")
    print(f"  Linhas (IP x janela): {len(linhas)}")
    print(f"  Janelas processadas: {total_janelas} ({janelas_suspeitas} suspeitas)")
    print(f"  Rótulo usado: {args.rotulo}")
    print("\nPróximo passo: python3 treinar_xgboost_ids.py")


if __name__ == "__main__":
    main()
