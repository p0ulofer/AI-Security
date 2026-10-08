"""
Extração de features por IP a partir dos trackers do EventPreprocessor.

Reaproveita os dados que já existem nos deques do pré-processador (nada é
recoletado), montando um vetor numérico por IP a cada janela. O FEATURE_SCHEMA
é a fonte única da verdade das colunas: treino e inferência devem importar
esta constante para garantir a mesma ordem de colunas nos dois lados.
"""

from typing import Dict, List

from preprocessor import EventPreprocessor

# ----------------------------------------------------------------------
# SCHEMA DE FEATURES — ordem idêntica no treino e na inferência
# ----------------------------------------------------------------------
FEATURE_SCHEMA: List[str] = [
    "portas_distintas_30s",
    "pacotes_syn_30s",
    "volume_bytes_30s",
    "conexoes_30s",
    "falhas_login_30s",
    "acessos_porta_sensivel",
]

# Janela de tempo usada por todas as features (mesma janela dos trackers)
JANELA_SEGUNDOS = 30.0


def _contar_conexoes_por_ip(preprocessor: EventPreprocessor) -> Dict[str, int]:
    """Reconta as conexões por IP remoto a partir do connections_buffer,
    aplicando os mesmos filtros usados dentro de process_window()."""
    conn_sightings_by_ip: Dict[str, int] = {}

    for snapshot in preprocessor.connections_buffer:
        for conn in snapshot:
            raddr = conn.get("remote_address", "N/A")
            laddr = conn.get("local_address", "N/A")

            if raddr == "N/A" or ":" not in raddr:
                continue
            if laddr == "N/A" or ":" not in laddr:
                continue

            try:
                remote_ip, _ = raddr.rsplit(":", 1)
                _, local_port = laddr.rsplit(":", 1)
                local_port_int = int(local_port)
            except ValueError:
                continue

            if remote_ip in ["127.0.0.1", "::1", "0.0.0.0", "::"]:
                continue

            # Ignorar lado servidor: porta local baixa significa que somos o destino
            if local_port_int < 1024:
                continue

            conn_sightings_by_ip[remote_ip] = conn_sightings_by_ip.get(remote_ip, 0) + 1

    return conn_sightings_by_ip


def extract_features_by_ip(preprocessor: EventPreprocessor, now: float) -> Dict[str, Dict[str, float]]:
    """Monta o vetor de features (FEATURE_SCHEMA) para cada IP presente em
    qualquer tracker do preprocessor, considerando os últimos 30 segundos.

    Retorna: {ip: {nome_feature: valor_float, ...}, ...}
    """
    janela_inicio = now - JANELA_SEGUNDOS

    # Tenta todas as conexões da janela atual (mesmos filtros de process_window)
    conn_sightings_by_ip = _contar_conexoes_por_ip(preprocessor)

    # Conjunto de IPs = união de todas as fontes de dados do pré-processador
    ips = set(preprocessor._port_scan_tracker.keys())
    ips.update(preprocessor._syn_flood_tracker.keys())
    ips.update(preprocessor._volume_tracker.keys())
    ips.update(preprocessor._failed_login_tracker.keys())
    ips.update(conn_sightings_by_ip.keys())

    features_by_ip: Dict[str, Dict[str, float]] = {}

    for ip in ips:
        # Portas distintas acessadas na janela (lê o deque sem alterá-lo)
        entradas_porta = preprocessor._port_scan_tracker.get(ip, ())
        portas_na_janela = [
            dport for ts, dport in entradas_porta
            if ts >= janela_inicio
        ]

        # Pacotes SYN na janela
        syn_times = preprocessor._syn_flood_tracker.get(ip, ())
        pacotes_syn = sum(1 for ts in syn_times if ts >= janela_inicio)

        # Volume em bytes na janela
        entradas_volume = preprocessor._volume_tracker.get(ip, ())
        volume_bytes = sum(size for ts, size in entradas_volume if ts >= janela_inicio)

        # Falhas de login na janela
        falhas_times = preprocessor._failed_login_tracker.get(ip, ())
        falhas_login = sum(1 for ts in falhas_times if ts >= janela_inicio)

        # Acesso a porta sensível (0/1): qualquer dport sensível na janela
        acessos_porta_sensivel = 1.0 if any(
            dport in preprocessor._sensitive_ports for dport in portas_na_janela
        ) else 0.0

        features_by_ip[ip] = {
            "portas_distintas_30s": float(len(set(portas_na_janela))),
            "pacotes_syn_30s": float(pacotes_syn),
            "volume_bytes_30s": float(volume_bytes),
            "conexoes_30s": float(conn_sightings_by_ip.get(ip, 0)),
            "falhas_login_30s": float(falhas_login),
            "acessos_porta_sensivel": acessos_porta_sensivel,
        }

    return features_by_ip
