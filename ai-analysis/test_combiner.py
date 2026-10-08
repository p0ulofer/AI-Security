"""
Teste simples do combiner.combine_signals (sem framework de teste).

Rodar a partir de ai-analysis/:
    python3 test_combiner.py
"""

from combiner import combine_signals

THRESHOLD = 0.7

# ----------------------------------------------------------------------
# (a) Só a heurística disparando
# ----------------------------------------------------------------------
regras = ["Varredura de portas via tráfego real detectada do IP 10.0.0.5"]
scores = {"10.0.0.5": 0.20, "10.0.0.9": 0.10}

deve_alertar, severidade, sinais = combine_signals(regras, scores, score_threshold=THRESHOLD)
assert deve_alertar is True, "(a) deveria alertar com a heurística disparada"
assert sinais == [], "(a) nenhum IP passou do threshold, não deveria haver sinais XGBoost"
assert 0.0 < severidade <= 10.0, "(a) severidade deveria ficar entre 0 e 10"
severidade_soh_regra = severidade

# ----------------------------------------------------------------------
# (b) Só o XGBoost acima do threshold
# ----------------------------------------------------------------------
deve_alertar, severidade, sinais = combine_signals([], {"1.2.3.4": 0.92}, score_threshold=THRESHOLD)
assert deve_alertar is True, "(b) deveria alertar com o XGBoost acima do threshold"
assert len(sinais) == 1, "(b) deveria ter exatamente um sinal XGBoost"
assert sinais[0] == "XGBoost: IP 1.2.3.4 com 92% de probabilidade de ataque", \
    f"(b) texto do sinal inesperado: {sinais[0]}"
assert 0.0 < severidade <= 10.0, "(b) severidade deveria ficar entre 0 e 10"

# ----------------------------------------------------------------------
# (c) Nenhum dos dois
# ----------------------------------------------------------------------
deve_alertar, severidade, sinais = combine_signals(
    [], {"1.2.3.4": 0.50, "5.6.7.8": 0.10}, score_threshold=THRESHOLD
)
assert deve_alertar is False, "(c) não deveria alertar sem regras e sem score acima do threshold"
assert sinais == [], "(c) scores abaixo do threshold não viram sinais"

# Caso extremo: nada de regras, nenhum score
deve_alertar, severidade, sinais = combine_signals([], {}, score_threshold=THRESHOLD)
assert deve_alertar is False, "(c) sem regras e sem scores não deveria alertar"
assert severidade <= 10.0, "(c) severidade deveria ficar entre 0 e 10"

# ----------------------------------------------------------------------
# (d) Os dois ao mesmo tempo
# ----------------------------------------------------------------------
regras = [
    "Varredura de portas via tráfego real detectada do IP 1.2.3.4 (tentou 15 portas diferentes nos últimos 30s)",
    "SYN flood via tráfego real detectado do IP 1.2.3.4 (60 pacotes SYN nos últimos 30s)",
]
scores = {"1.2.3.4": 0.95, "9.9.9.9": 0.30}

deve_alertar, severidade, sinais = combine_signals(regras, scores, score_threshold=THRESHOLD)
assert deve_alertar is True, "(d) deveria alertar com heurística e XGBoost juntos"
assert len(sinais) == 1, "(d) só o IP acima do threshold deveria gerar sinal"
assert "1.2.3.4" in sinais[0] and "95%" in sinais[0], f"(d) sinal inesperado: {sinais[0]}"
assert severidade > severidade_soh_regra, \
    "(d) heurística + XGBoost juntos deveriam dar severidade maior que só heurística"
assert severidade <= 10.0, "(d) severidade deveria ser capada em 10"

# ----------------------------------------------------------------------
# Bônus: severidade sempre capada em 10 mesmo com muitas regras e score alto
# ----------------------------------------------------------------------
muitas_regras = [f"Regra simulada {i}" for i in range(10)]
_, severidade, _ = combine_signals(muitas_regras, {"1.2.3.4": 1.0}, score_threshold=THRESHOLD)
assert severidade == 10.0, f"severidade deveria ser capada em 10, veio {severidade}"

# ----------------------------------------------------------------------
# Threshold configurável
# ----------------------------------------------------------------------
deve_alertar, _, _ = combine_signals([], {"1.2.3.4": 0.50}, score_threshold=0.4)
assert deve_alertar is True, "threshold menor deveria disparar com score menor"
deve_alertar, _, _ = combine_signals([], {"1.2.3.4": 0.50}, score_threshold=0.9)
assert deve_alertar is False, "threshold maior não deveria disparar com score menor"

print("OK: todos os testes do combiner passaram (casos a, b, c, d + limites).")
