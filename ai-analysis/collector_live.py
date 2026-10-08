# collector_live.py
#
# INSTRUÇÕES DE EXECUÇÃO COM PRIVILÉGIOS (SUDO):
# Como o Scapy realiza a captura direta de pacotes na interface de rede em modo promíscuo,
# é necessário executar este script com privilégios de superusuário (root/sudo):
#
#   sudo python3 main.py --live --iface <interface> [outros argumentos]
#
# Certifique-se de que a dependência scapy esteja instalada para o usuário root (ou use sudo pip install scapy).

import os
import time
import threading
import queue
import psutil
from typing import Dict, List, Any

# Importa os módulos necessários do Scapy de forma segura
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
except ImportError:
    # Caso ocorra no ambiente de desenvolvimento/análise sem scapy instalado
    pass

class LivePacketCollector:
    def __init__(self, iface: str = None):
        self.event_queue = queue.Queue()
        self.running = False
        self.thread = None
        
        # Detecta automaticamente a interface principal se nenhuma for fornecida
        if iface:
            self.iface = iface
        else:
            try:
                self.iface = str(conf.iface)
            except Exception:
                self.iface = None
        print(f"Live Collector: Interface de captura configurada para: {self.iface}")

    def _packet_callback(self, packet):
        if not self.running:
            return
            
        try:
            # Verifica se o pacote tem a camada IP (IPv4 ou IPv6)
            if not packet.haslayer(IP):
                return
                
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(packet)
            
            proto = "OTHER"
            sport = None
            dport = None
            flags = ""
            
            # Se for TCP
            if packet.haslayer(TCP):
                proto = "TCP"
                tcp_layer = packet[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                # Mapeamento de flags
                flag_list = []
                tcp_flags = str(tcp_layer.flags)
                if 'S' in tcp_flags:
                    flag_list.append("SYN")
                if 'R' in tcp_flags:
                    flag_list.append("RST")
                if 'F' in tcp_flags:
                    flag_list.append("FIN")
                if 'A' in tcp_flags:
                    flag_list.append("ACK")
                flags = ",".join(flag_list)
                
            # Se for UDP
            elif packet.haslayer(UDP):
                proto = "UDP"
                udp_layer = packet[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport
                
            # Se for ICMP
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                
            # Formata a string de log similar ao original para manter compatibilidade e legibilidade
            content = f"PACKET: src={src_ip}:{sport if sport else ''} -> dst={dst_ip}:{dport if dport else ''} proto={proto} size={size} bytes"
            if flags:
                content += f" flags=[{flags}]"
                
            event = {
                "type": "log",
                "source": "live_traffic",
                "timestamp": time.time(),
                "content": content,
                "packet_data": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": sport,
                    "dport": dport,
                    "proto": proto,
                    "size": size,
                    "flags": flags
                }
            }
            self.event_queue.put(event)
            
        except Exception as e:
            # Captura erros silenciosamente para evitar quebrar o loop de captura
            pass

    def _sniff_loop(self):
        print(f"Live Collector: Iniciando captura de pacotes na interface {self.iface}...")
        try:
            # Executa o sniff em loop contínuo até self.running ser False
            # O filter "ip" captura apenas tráfego IP (TCP/UDP/ICMP)
            sniff(
                iface=self.iface,
                prn=self._packet_callback,
                filter="ip",
                store=0,
                stop_filter=lambda p: not self.running
            )
        except PermissionError:
            self.event_queue.put({
                "type": "error",
                "source": "live_traffic",
                "timestamp": time.time(),
                "content": "Permissão negada ao capturar pacotes. Execute como root/sudo."
            })
        except Exception as e:
            self.event_queue.put({
                "type": "error",
                "source": "live_traffic",
                "timestamp": time.time(),
                "content": f"Erro na captura live: {str(e)}"
            })

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def get_new_events(self) -> List[Dict[str, Any]]:
        events = []
        while not self.event_queue.empty():
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def get_active_connections(self) -> List[Dict[str, Any]]:
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status,
                    "pid": conn.pid
                })
        except PermissionError:
            pass
        except Exception as e:
            print(f"Live Collector Error: Falha ao listar conexões: {e}")
        return connections
