import re
import time
from collections import deque
from typing import List, Dict, Any, Tuple

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class EventPreprocessor:
    def __init__(self, ssh_fail_threshold: int = 5, conn_spike_threshold: int = 15,
                 sliding_window_seconds: int = 60, alert_suppression_seconds: int = 60):
        self.ssh_fail_threshold = ssh_fail_threshold
        self.conn_spike_threshold = conn_spike_threshold
        self.sliding_window_seconds = sliding_window_seconds
        self.alert_suppression_seconds = alert_suppression_seconds
        self.log_buffer: List[Dict[str, Any]] = []
        self.connections_buffer: List[List[Dict[str, Any]]] = []
        # Rastreador persistente de janela deslizante: não é limpo entre janelas
        # Chave: IP, Valor: deque de timestamps (float) das falhas de login
        self._failed_login_tracker: Dict[str, deque] = {}
        # Supressão de alertas por IP: evita re-alertas repetidos do mesmo IP
        # Chave: IP, Valor: timestamp do último alerta gerado
        self._last_alert_time: Dict[str, float] = {}

    def add_log(self, log_event: Dict[str, Any]):
        self.log_buffer.append(log_event)

        # Atualiza imediatamente o rastreador de janela deslizante
        content = log_event.get("content", "")
        content_lower = content.lower()
        is_fail = (
            "failed password" in content_lower or
            "authentication failure" in content_lower or
            "invalid user" in content_lower or
            "senha incorreta" in content_lower or
            "falha de autenticação" in content_lower or
            "usuário inválido" in content_lower
        )
        if is_fail:
            now = time.time()
            ips = IP_RE.findall(content)
            for ip in (ips if ips else ["unknown_ip"]):
                if ip not in self._failed_login_tracker:
                    self._failed_login_tracker[ip] = deque()
                self._failed_login_tracker[ip].append(now)

    def add_connections_snapshot(self, connections: List[Dict[str, Any]]):
        self.connections_buffer.append(connections)

    def clear(self):
        self.log_buffer.clear()
        self.connections_buffer.clear()
        # _failed_login_tracker e _last_alert_time são mantidos intencionalmente
        # entre janelas para a janela deslizante e supressão de alertas

    def process_window(self) -> Tuple[bool, List[str], str]:
        """
        Processes the accumulated logs and network snapshots in the current window.
        Returns:
            - is_suspicious (bool): True if any simple rule triggered.
            - triggered_rules (List[str]): List of names of the rules that triggered.
            - structured_summary (str): Text summarizing the window's activity.
        """
        triggered_rules = []
        
        # 1. Analyze logs for failed logins
        sudo_escalations = []
        general_warnings = []

        for log in self.log_buffer:
            content = log.get("content", "")
            content_lower = content.lower()

            # Check for sudo/root actions (supports English and Portuguese)
            if ("session opened for user root" in content_lower or
                    "accepted password for root" in content_lower or
                    "sessão aberta para o usuário root" in content_lower or
                    "senha aceita para root" in content_lower):
                sudo_escalations.append(content)

            # Check for segfaults or core dumps (supports English and Portuguese)
            if ("segfault" in content_lower or "core dump" in content_lower or
                    "denied" in content_lower or "falha_de_segmentacao" in content_lower or
                    "negado" in content_lower):
                general_warnings.append(content)

        # Apply Rule 1 (Janela Deslizante): conta falhas de login dos últimos N segundos
        # Isso elimina o problema de divisão de janela fixa (window splitting)
        now = time.time()
        failed_logins_by_ip: Dict[str, int] = {}
        for ip, timestamps in self._failed_login_tracker.items():
            # Remove entradas mais antigas que a janela deslizante
            while timestamps and now - timestamps[0] > self.sliding_window_seconds:
                timestamps.popleft()
            if timestamps:
                failed_logins_by_ip[ip] = len(timestamps)

        for ip, count in failed_logins_by_ip.items():
            if count >= self.ssh_fail_threshold:
                last_alerted = self._last_alert_time.get(ip, 0)
                tempo_desde_ultimo = now - last_alerted
                if tempo_desde_ultimo > self.alert_suppression_seconds:
                    # Dispara o alerta e registra o momento
                    triggered_rules.append(f"Alta taxa de falha de login do IP {ip} ({count} falhas nos últimos {self.sliding_window_seconds}s)")
                    self._last_alert_time[ip] = now
                else:
                    # Alerta suprimido — informa no terminal sem gerar novo alerta
                    restante = int(self.alert_suppression_seconds - tempo_desde_ultimo)
                    print(f"  [Supressão] Alerta de força bruta para {ip} suprimido. Próximo permitido em {restante}s.")

        # Apply Rule 2: Root privilege execution / logins
        if sudo_escalations:
            triggered_rules.append(f"Sessão/login de root detectado ({len(sudo_escalations)} vezes)")

        # Apply Rule 3: System errors / segfaults
        if general_warnings:
            triggered_rules.append(f"Exploração em potencial ou falhas de sistema detectadas ({len(general_warnings)} vezes)")

        # 2. Analyze network connections
        unique_remote_ports = {}
        conn_sightings_by_ip = {}

        if self.connections_buffer:
            # Analyze all connection snapshots taken during this window
            for snapshot in self.connections_buffer:
                for conn in snapshot:
                    raddr = conn.get("remote_address", "N/A")
                    status = conn.get("status", "")
                    
                    if raddr != "N/A" and ":" in raddr:
                        try:
                            ip, port = raddr.rsplit(":", 1)
                        except ValueError:
                            continue
                        
                        # Filter out localhost and broadcast/any addresses
                        if ip not in ["127.0.0.1", "::1", "0.0.0.0", "::"]:
                            conn_sightings_by_ip[ip] = conn_sightings_by_ip.get(ip, 0) + 1
                            
                            if ip not in unique_remote_ports:
                                unique_remote_ports[ip] = set()
                            unique_remote_ports[ip].add(port)
            
            # Check for connection counts per remote IP
            for ip, count in conn_sightings_by_ip.items():
                ports_count = len(unique_remote_ports.get(ip, set()))
                if ports_count >= 5:
                    triggered_rules.append(f"Varredura/sondagem de portas em potencial vinda de {ip} (direcionada a {ports_count} portas diferentes)")
                
                # Rule: Connection spike
                if count >= self.conn_spike_threshold:
                    triggered_rules.append(f"Pico de conexões do IP {ip} ({count} conexões capturadas)")

        is_suspicious = len(triggered_rules) > 0

        # Format a clean structured summary
        summary_lines = []
        summary_lines.append("--- RESUMO DE ATIVIDADES DA JANELA ---")
        summary_lines.append(f"Total de eventos de log capturados: {len(self.log_buffer)}")
        summary_lines.append(f"Total de capturas de conexão: {len(self.connections_buffer)}")
        
        if failed_logins_by_ip:
            summary_lines.append("\nLogins malsucedidos por IP:")
            for ip, count in failed_logins_by_ip.items():
                summary_lines.append(f"  - {ip}: {count} tentativas")
                
        if sudo_escalations:
            summary_lines.append("\nLogins de Root / eventos de sudo:")
            for e in sudo_escalations[:5]:  # Limit to 5
                summary_lines.append(f"  - {e}")
                
        if general_warnings:
            summary_lines.append("\nAvisos/erros do sistema:")
            for w in general_warnings[:5]:
                summary_lines.append(f"  - {w}")

        if unique_remote_ports:
            summary_lines.append("\nConexões ativas/estabelecidas observadas nesta janela:")
            for ip, ports in unique_remote_ports.items():
                ports_list = sorted(list(ports))
                if len(ports_list) > 5:
                    ports_str = ", ".join(ports_list[:5]) + f"... (+{len(ports_list)-5} mais)"
                else:
                    ports_str = ", ".join(ports_list)
                summary_lines.append(f"  - IP Remoto: {ip} -> Portas locais direcionadas: [{ports_str}]")

        if triggered_rules:
            summary_lines.append("\nRegras heurísticas ativadas:")
            for rule in triggered_rules:
                summary_lines.append(f"  [ATIVADA] {rule}")
        else:
            summary_lines.append("\nNenhuma regra heurística ativada.")

        structured_summary = "\n".join(summary_lines)

        return is_suspicious, triggered_rules, structured_summary
