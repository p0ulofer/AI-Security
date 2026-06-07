import re
import time
from collections import deque
from typing import List, Dict, Any, Tuple

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class EventPreprocessor:
    def __init__(self, ssh_fail_threshold: int = 5, conn_spike_threshold: int = 15,
                 sliding_window_seconds: int = 60, alert_suppression_seconds: int = 60,
                 port_scan_threshold: int = 10, syn_flood_threshold: int = 50,
                 volume_mb_threshold: float = 5.0):
        self.ssh_fail_threshold = ssh_fail_threshold
        self.conn_spike_threshold = conn_spike_threshold
        self.sliding_window_seconds = sliding_window_seconds
        self.alert_suppression_seconds = alert_suppression_seconds
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.volume_mb_threshold = volume_mb_threshold
        self.log_buffer: List[Dict[str, Any]] = []
        self.connections_buffer: List[List[Dict[str, Any]]] = []
        # Rastreador persistente de janela deslizante: não é limpo entre janelas
        # Chave: IP, Valor: deque de timestamps (float) das falhas de login
        self._failed_login_tracker: Dict[str, deque] = {}
        # Supressão de alertas por IP: evita re-alertas repetidos do mesmo IP
        # Chave: IP, Valor: timestamp do último alerta gerado
        self._last_alert_time: Dict[str, float] = {}

        # Rastreadores persistentes para tráfego live (Scapy)
        self._port_scan_tracker: Dict[str, deque] = {}  # IP -> deque((timestamp, port))
        self._syn_flood_tracker: Dict[str, deque] = {}  # IP -> deque(timestamp)
        self._volume_tracker: Dict[str, deque] = {}     # IP -> deque((timestamp, size))
        self._sensitive_ports = {22, 23, 3389, 445, 1433}

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

        # Se for um evento de pacote live, atualiza os rastreadores heurísticos específicos de rede
        packet_data = log_event.get("packet_data")
        if packet_data:
            now = time.time()
            src_ip = packet_data.get("src_ip")
            dport = packet_data.get("dport")
            proto = packet_data.get("proto")
            size = packet_data.get("size", 0)
            flags = packet_data.get("flags", "")
            
            if src_ip:
                # 1. Port scan tracker
                if dport is not None:
                    if src_ip not in self._port_scan_tracker:
                        self._port_scan_tracker[src_ip] = deque()
                    self._port_scan_tracker[src_ip].append((now, dport))
                    
                # 2. SYN flood tracker
                if proto == "TCP" and "SYN" in flags:
                    if src_ip not in self._syn_flood_tracker:
                        self._syn_flood_tracker[src_ip] = deque()
                    self._syn_flood_tracker[src_ip].append(now)
                    
                # 3. Volume tracker
                if src_ip not in self._volume_tracker:
                    self._volume_tracker[src_ip] = deque()
                self._volume_tracker[src_ip].append((now, size))

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

        # 3. Analisa as regras heurísticas de pacotes em tempo real (Scapy live)
        now = time.time()
        
        # Heurística: Port scan (mesmo IP tentando mais de 10 portas diferentes em 30 segundos)
        for ip, attempts in list(self._port_scan_tracker.items()):
            while attempts and now - attempts[0][0] > 30:
                attempts.popleft()
            if attempts:
                unique_ports = {port for ts, port in attempts}
                if len(unique_ports) > self.port_scan_threshold:
                    triggered_rules.append(
                        f"Varredura de portas via tráfego real detectada do IP {ip} (tentou {len(unique_ports)} portas diferentes nos últimos 30s)"
                    )
            else:
                self._port_scan_tracker.pop(ip, None)
                
        # Heurística: SYN flood (mais de 50 pacotes SYN do mesmo IP em 30 segundos)
        for ip, syn_times in list(self._syn_flood_tracker.items()):
            while syn_times and now - syn_times[0] > 30:
                syn_times.popleft()
            if len(syn_times) > self.syn_flood_threshold:
                triggered_rules.append(
                    f"SYN flood via tráfego real detectado do IP {ip} ({len(syn_times)} pacotes SYN nos últimos 30s)"
                )
            if not syn_times:
                self._syn_flood_tracker.pop(ip, None)
                
        # Heurística: Volume anômalo (um IP enviando mais de 5MB em 30 segundos)
        for ip, vol_entries in list(self._volume_tracker.items()):
            while vol_entries and now - vol_entries[0][0] > 30:
                vol_entries.popleft()
            if vol_entries:
                total_bytes = sum(size for ts, size in vol_entries)
                if total_bytes > self.volume_mb_threshold * 1024 * 1024:
                    mb_sent = total_bytes / (1024 * 1024)
                    triggered_rules.append(
                        f"Volume anômalo via tráfego real detectado do IP {ip} ({mb_sent:.2f}MB enviados nos últimos 30s)"
                    )
            else:
                self._volume_tracker.pop(ip, None)

        # Heurística: Conexão em portas sensíveis (qualquer acesso às portas 22, 23, 3389, 445, 1433 na janela atual)
        sensitive_accesses = []
        for log in self.log_buffer:
            p_data = log.get("packet_data")
            if p_data:
                dport = p_data.get("dport")
                if dport in self._sensitive_ports:
                    src = p_data.get("src_ip")
                    proto = p_data.get("proto")
                    sensitive_accesses.append((src, dport, proto))
                    
        if sensitive_accesses:
            unique_accesses = set(sensitive_accesses)
            for src, dport, proto in sorted(unique_accesses):
                triggered_rules.append(
                    f"Acesso a porta sensível detectado via tráfego real: IP {src} acessou porta {dport} ({proto})"
                )

        is_suspicious = len(triggered_rules) > 0

        # Format a clean structured summary
        summary_lines = []
        summary_lines.append("--- RESUMO DE ATIVIDADES DA JANELA ---")
        
        # Filtra eventos de log padrão vs tráfego live para relatório mais preciso
        standard_logs = [log for log in self.log_buffer if log.get("source") != "live_traffic"]
        live_packets = [log.get("packet_data") for log in self.log_buffer if log.get("source") == "live_traffic"]
        
        summary_lines.append(f"Total de eventos de log capturados: {len(standard_logs)}")
        summary_lines.append(f"Total de pacotes de tráfego real capturados: {len(live_packets)}")
        summary_lines.append(f"Total de capturas de conexão: {len(self.connections_buffer)}")
        
        # Se houver pacotes live, adiciona resumo do tráfego real
        if live_packets:
            summary_lines.append("\nResumo do Tráfego Real Capturado:")
            # Contagem de protocolos
            proto_counts = {}
            for p in live_packets:
                proto = p.get("proto", "OUTRO")
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
            for proto, count in proto_counts.items():
                summary_lines.append(f"  - Protocolo {proto}: {count} pacotes")
        
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
