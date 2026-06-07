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
        self._failed_login_tracker: Dict[str, deque] = {}
        self._last_alert_time: Dict[str, float] = {}
        self._port_scan_tracker: Dict[str, deque] = {}
        self._syn_flood_tracker: Dict[str, deque] = {}
        self._volume_tracker: Dict[str, deque] = {}
        self._sensitive_ports = {22, 23, 3389, 445, 1433}

    def add_log(self, log_event: Dict[str, Any]):
        self.log_buffer.append(log_event)

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

        packet_data = log_event.get("packet_data")
        if packet_data:
            now = time.time()
            src_ip = packet_data.get("src_ip")
            dst_ip = packet_data.get("dst_ip")
            dport = packet_data.get("dport")
            proto = packet_data.get("proto")
            size = packet_data.get("size", 0)
            flags = packet_data.get("flags", "")

            # Ignorar pacotes de resposta legítimos:
            # se o destino é o próprio WSL e a origem é um IP externo,
            # significa que é uma resposta a uma requisição nossa — não uma ameaça
            WSL_LOCAL_IP = "172.29.105.246"
            is_response_traffic = (dst_ip == WSL_LOCAL_IP and src_ip != WSL_LOCAL_IP)
            
            if src_ip and not is_response_traffic:
                if dport is not None:
                    if src_ip not in self._port_scan_tracker:
                        self._port_scan_tracker[src_ip] = deque()
                    self._port_scan_tracker[src_ip].append((now, dport))

                if proto == "TCP" and "SYN" in flags:
                    if src_ip not in self._syn_flood_tracker:
                        self._syn_flood_tracker[src_ip] = deque()
                    self._syn_flood_tracker[src_ip].append(now)

                if src_ip not in self._volume_tracker:
                    self._volume_tracker[src_ip] = deque()
                self._volume_tracker[src_ip].append((now, size))

    def add_connections_snapshot(self, connections: List[Dict[str, Any]]):
        self.connections_buffer.append(connections)

    def clear(self):
        self.log_buffer.clear()
        self.connections_buffer.clear()

    def process_window(self) -> Tuple[bool, List[str], str]:
        triggered_rules = []

        sudo_escalations = []
        general_warnings = []

        for log in self.log_buffer:
            content = log.get("content", "")
            content_lower = content.lower()

            if ("session opened for user root" in content_lower or
                    "accepted password for root" in content_lower or
                    "sessão aberta para o usuário root" in content_lower or
                    "senha aceita para root" in content_lower):
                sudo_escalations.append(content)

            if ("segfault" in content_lower or "core dump" in content_lower or
                    "denied" in content_lower or "falha_de_segmentacao" in content_lower or
                    "negado" in content_lower):
                general_warnings.append(content)

        now = time.time()
        failed_logins_by_ip: Dict[str, int] = {}
        for ip, timestamps in self._failed_login_tracker.items():
            while timestamps and now - timestamps[0] > self.sliding_window_seconds:
                timestamps.popleft()
            if timestamps:
                failed_logins_by_ip[ip] = len(timestamps)

        for ip, count in failed_logins_by_ip.items():
            if count >= self.ssh_fail_threshold:
                last_alerted = self._last_alert_time.get(ip, 0)
                tempo_desde_ultimo = now - last_alerted
                if tempo_desde_ultimo > self.alert_suppression_seconds:
                    triggered_rules.append(f"Alta taxa de falha de login do IP {ip} ({count} falhas nos últimos {self.sliding_window_seconds}s)")
                    self._last_alert_time[ip] = now
                else:
                    restante = int(self.alert_suppression_seconds - tempo_desde_ultimo)
                    print(f"  [Supressão] Alerta de força bruta para {ip} suprimido. Próximo permitido em {restante}s.")

        if sudo_escalations:
            triggered_rules.append(f"Sessão/login de root detectado ({len(sudo_escalations)} vezes)")

        if general_warnings:
            triggered_rules.append(f"Exploração em potencial ou falhas de sistema detectadas ({len(general_warnings)} vezes)")

        # Análise de conexões — rastreia porta LOCAL (destino real) e não porta efêmera de origem
        unique_local_ports_by_remote_ip = {}
        conn_sightings_by_ip = {}

        if self.connections_buffer:
            for snapshot in self.connections_buffer:
                for conn in snapshot:
                    raddr = conn.get("remote_address", "N/A")
                    laddr = conn.get("local_address", "N/A")

                    if raddr == "N/A" or ":" not in raddr:
                        continue
                    if laddr == "N/A" or ":" not in laddr:
                        continue

                    try:
                        remote_ip, remote_port = raddr.rsplit(":", 1)
                        _, local_port = laddr.rsplit(":", 1)
                        local_port_int  = int(local_port)
                        remote_port_int = int(remote_port)
                    except ValueError:
                        continue

                    if remote_ip in ["127.0.0.1", "::1", "0.0.0.0", "::"]:
                        continue

                    # Ignorar lado servidor: porta local baixa significa que somos o destino
                    if local_port_int < 1024:
                        continue

                    conn_sightings_by_ip[remote_ip] = conn_sightings_by_ip.get(remote_ip, 0) + 1

                    if remote_ip not in unique_local_ports_by_remote_ip:
                        unique_local_ports_by_remote_ip[remote_ip] = set()
                    # Registrar porta REMOTA (destino real do ataque)
                    unique_local_ports_by_remote_ip[remote_ip].add(str(remote_port_int))

            for ip, count in conn_sightings_by_ip.items():
                ports_count = len(unique_local_ports_by_remote_ip.get(ip, set()))
                if ports_count >= 5:
                    triggered_rules.append(f"Varredura/sondagem de portas em potencial vinda de {ip} (direcionada a {ports_count} portas diferentes)")
                if count >= self.conn_spike_threshold:
                    last_alerted = self._last_alert_time.get(ip, 0)
                    if now - last_alerted > self.alert_suppression_seconds:
                        triggered_rules.append(f"Pico de conexões do IP {ip} ({count} conexões capturadas)")
                        self._last_alert_time[ip] = now

        # Heurísticas de pacotes em tempo real (Scapy)
        now = time.time()

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

        for ip, syn_times in list(self._syn_flood_tracker.items()):
            while syn_times and now - syn_times[0] > 30:
                syn_times.popleft()
            if len(syn_times) > self.syn_flood_threshold:
                triggered_rules.append(
                    f"SYN flood via tráfego real detectado do IP {ip} ({len(syn_times)} pacotes SYN nos últimos 30s)"
                )
            if not syn_times:
                self._syn_flood_tracker.pop(ip, None)

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

        # Monta o resumo estruturado
        summary_lines = []
        summary_lines.append("--- RESUMO DE ATIVIDADES DA JANELA ---")

        standard_logs = [log for log in self.log_buffer if log.get("source") != "live_traffic"]
        live_packets = [log.get("packet_data") for log in self.log_buffer if log.get("source") == "live_traffic"]

        summary_lines.append(f"Total de eventos de log capturados: {len(standard_logs)}")
        summary_lines.append(f"Total de pacotes de tráfego real capturados: {len(live_packets)}")
        summary_lines.append(f"Total de capturas de conexão: {len(self.connections_buffer)}")

        if live_packets:
            summary_lines.append("\nResumo do Tráfego Real Capturado:")
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
            for e in sudo_escalations[:5]:
                summary_lines.append(f"  - {e}")

        if general_warnings:
            summary_lines.append("\nAvisos/erros do sistema:")
            for w in general_warnings[:5]:
                summary_lines.append(f"  - {w}")

        if unique_local_ports_by_remote_ip:
            summary_lines.append("\nConexões ativas observadas nesta janela:")
            for ip, ports in unique_local_ports_by_remote_ip.items():
                ports_list = sorted(list(ports))
                if len(ports_list) > 5:
                    ports_str = ", ".join(ports_list[:5]) + f"... (+{len(ports_list)-5} mais)"
                else:
                    ports_str = ", ".join(ports_list)
                summary_lines.append(f"  - IP Remoto: {ip} -> Porta(s) local(is) alvo: [{ports_str}]")

        if triggered_rules:
            summary_lines.append("\nRegras heurísticas ativadas:")
            for rule in triggered_rules:
                summary_lines.append(f"  [ATIVADA] {rule}")
        else:
            summary_lines.append("\nNenhuma regra heurística ativada.")

        structured_summary = "\n".join(summary_lines)

        return is_suspicious, triggered_rules, structured_summary