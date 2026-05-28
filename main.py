import time
import argparse
import sys
from collector import LogCollector
from preprocessor import EventPreprocessor
from ollama_client import OllamaClient
from alerter import Alerter

def main():
    parser = argparse.ArgumentParser(description="Local LLM Network Threat Detection System")
    parser.add_argument("--window", type=int, default=30, help="Window size in seconds for aggregation (default: 30)")
    parser.add_argument("--conn-interval", type=int, default=5, help="Interval in seconds for network connection snapshots (default: 5)")
    parser.add_argument("--db", type=str, default="threats.db", help="Path to SQLite database")
    parser.add_argument("--model", type=str, default="mistral:7b-instruct-q4_K_M", help="Ollama model name")
    parser.add_argument("--url", type=str, default="http://localhost:11434", help="Ollama base URL")
    parser.add_argument("--logs", type=str, default="/var/log/auth.log,/var/log/syslog", help="Comma-separated paths to log files to tail")
    
    args = parser.parse_args()

    print("Inicializando componentes...")
    # Read specified log files
    log_paths = [p.strip() for p in args.logs.split(",")]
    collector = LogCollector(log_paths=log_paths)
    preprocessor = EventPreprocessor(ssh_fail_threshold=5, conn_spike_threshold=10)
    ollama = OllamaClient(base_url=args.url, model=args.model)
    alerter = Alerter(db_path=args.db)

    print("Iniciando threads coletoras de logs...")
    collector.start()

    window_size = args.window
    conn_interval = args.conn_interval
    
    last_window_time = time.time()
    last_conn_time = time.time()

    print(f"O sistema está em execução. Janela de agregação: {window_size}s. Intervalo de captura de rede: {conn_interval}s.")
    print("Pressione Ctrl+C para parar.")

    try:
        while True:
            current_time = time.time()

            # 1. Fetch new log events and add to preprocessor
            new_logs = collector.get_new_events()
            for log in new_logs:
                # If there's an error log (e.g. Permission Denied), print it and exit
                if log.get("type") == "error":
                    print(f"\n[ERRO FATAL] {log.get('content')}")
                    print("Por favor, execute este script com privilégios elevados (sudo python3 main.py) ou garanta que as permissões estejam corretas.")
                    sys.exit(1)
                preprocessor.add_log(log)

            # 2. Check if it's time to take a connection snapshot
            if current_time - last_conn_time >= conn_interval:
                conns = collector.get_active_connections()
                preprocessor.add_connections_snapshot(conns)
                last_conn_time = current_time

            # 3. Check if the window has elapsed
            if current_time - last_window_time >= window_size:
                print(f"\nProcessando janela de {window_size} segundos ({len(preprocessor.log_buffer)} eventos de log, {len(preprocessor.connections_buffer)} capturas de conexão)...")
                is_suspicious, rules, summary = preprocessor.process_window()

                if is_suspicious:
                    print(f"Heurísticas ativadas: {', '.join(rules)}")
                    print("Enviando detalhes da janela suspeita para o modelo Ollama local para classificação de ameaças...")
                    
                    analysis = ollama.analyze_event(summary)
                    
                    # Trigger alert with LLM output
                    alerter.trigger_alert(
                        threat_type=analysis.get("classification", "Desconhecido"),
                        severity_score=analysis.get("score", 1),
                        explanation=analysis.get("explanation", "N/A"),
                        details=summary
                    )
                else:
                    print("Análise da janela concluída: Normal (sem alertas).")

                # Clear preprocessor buffer for next window
                preprocessor.clear()
                last_window_time = current_time

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nParando o sistema...")
    finally:
        collector.stop()
        print("Coletor parado. Saindo.")

if __name__ == "__main__":
    main()
