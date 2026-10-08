"""
Combinação dos dois sinais de detecção em um único veredito:

1. Heurísticas do EventPreprocessor (regras disparadas)
2. Score de probabilidade do classificador XGBoost por IP

O veredito (alertar ou não + severidade final) é decidido ANTES de chamar o
LLM, e os sinais do XGBoost são devolvidos em texto para serem acrescentados
ao structured_summary enviado ao modelo.
"""

from typing import Dict, List, Tuple

# Severidade base atribuída quando pelo menos uma regra heurística dispara
SEVERIDADE_BASE_REGRA = 4.0
# Bônus de severidade por regra adicional disparada
BONUS_POR_REGRA = 1.0
# Bônus máximo que o melhor score do XGBoost pode somar à severidade
BONUS_MAXIMO_XGBOOST = 5.0
# Severidade máxima final (mesma escala 1-10 usada pelo LLM)
SEVERIDADE_MAXIMA = 10.0


def combine_signals(triggered_rules: List[str],
                    ip_scores: Dict[str, float],
                    score_threshold: float = 0.7) -> Tuple[bool, float, List[str]]:
    """Decide se deve alertar e calcula a severidade final combinada.

    Args:
        triggered_rules: regras heurísticas disparadas na janela.
        ip_scores: probabilidade de ataque (0-1) do XGBoost por IP.
        score_threshold: a partir de qual probabilidade o XGBoost alerta.

    Returns:
        (deve_alertar, severidade_final, sinais_xgboost)
        - deve_alertar: True se a heurística disparou OU algum IP passou do threshold.
        - severidade_final: severidade base pelas regras + bônus proporcional
          ao melhor score do XGBoost, capada em 10.
        - sinais_xgboost: textos tipo "XGBoost: IP 1.2.3.4 com 92% de
          probabilidade de ataque" para ir ao structured_summary.
    """
    heuristica_disparou = len(triggered_rules) > 0

    # IPs que atingiram o threshold do classificador
    ips_acima = {
        ip: score for ip, score in ip_scores.items()
        if score >= score_threshold
    }
    xgboost_disparou = len(ips_acima) > 0

    deve_alertar = heuristica_disparou or xgboost_disparou

    # --- Severidade base: vem das regras heurísticas ---
    if heuristica_disparou:
        severidade = SEVERIDADE_BASE_REGRA + BONUS_POR_REGRA * (len(triggered_rules) - 1)
    else:
        severidade = 0.0

    # --- Bônus proporcional ao melhor score do XGBoost (capado em 10) ---
    melhor_score = max(ip_scores.values()) if ip_scores else 0.0
    severidade += BONUS_MAXIMO_XGBOOST * melhor_score
    severidade = min(severidade, SEVERIDADE_MAXIMA)

    # --- Sinais em texto para o LLM ---
    sinais_xgboost = [
        f"XGBoost: IP {ip} com {int(round(score * 100))}% de probabilidade de ataque"
        for ip, score in sorted(ips_acima.items(), key=lambda item: item[1], reverse=True)
    ]

    return deve_alertar, severidade, sinais_xgboost
