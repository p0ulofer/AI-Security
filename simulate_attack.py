import time
import os
import datetime

def simulate():
    auth_log = "mock_auth.log"
    syslog = "mock_syslog"

    print("Initializing mock log files...")
    # Truncate and open log files
    with open(auth_log, "w") as f:
        f.write("")
    with open(syslog, "w") as f:
        f.write("")

    print(f"Mock logs initialized. Please start 'main.py' in a separate terminal with:")
    print(f"  python3 main.py --logs mock_auth.log,mock_syslog --window 15 --conn-interval 3")
    print("\nWaiting 5 seconds for you to start main.py...")
    time.sleep(5)

    print("\n[Simulador] Passo 1: Injetando logs normais do sistema (Não devem acionar o LLM)")
    now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    with open(syslog, "a") as f:
        f.write(f"{now} hostname systemd[1]: Iniciou o Agendador de Comandos Periódicos.\n")
        f.write(f"{now} hostname systemd[1]: Atingiu o alvo Sistema Multi-Usuário.\n")
    with open(auth_log, "a") as f:
        f.write(f"{now} hostname sshd[12345]: Conexão fechada pelo usuário autenticador guest 192.168.1.50 porta 54321 [pré-autenticação]\n")
    
    print("[Simulador] Aguardando 10 segundos...")
    time.sleep(10)

    print("\n[Simulador] Passo 2: Injetando atividade suspeita de Força Bruta SSH (6 falhas de login em 5 segundos)")
    for i in range(6):
        now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        with open(auth_log, "a") as f:
            f.write(f"{now} hostname sshd[22222]: Senha incorreta para usuário inválido admin{i} de 192.168.1.99 porta {50000+i} ssh2\n")
        print(f"  - Injetou login com falha {i+1}/6")
        time.sleep(0.5)

    print("[Simulador] Aguardando 20 segundos...")
    time.sleep(20)

    print("\n[Simulador] Passo 3: Injetando escalada de privilégios para root e erros de sistema")
    now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    with open(auth_log, "a") as f:
        f.write(f"{now} hostname sudo: pam_unix(sudo:session): sessão aberta para o usuário root por (uid=1000)\n")
    with open(syslog, "a") as f:
        f.write(f"{now} hostname kernel: [12345.678] main_app[8888]: falha_de_segmentacao em 0 ip 0000000000000000 sp 00007ffd12345678 erro 4 em main_app\n")
    print("  - Injetou abertura de sessão root e falha de segmentação no kernel")

    print("[Simulador] Simulação concluída. Mantenha o main.py rodando por mais 15 segundos para ver o processamento de todos os alertas.")

if __name__ == "__main__":
    simulate()
