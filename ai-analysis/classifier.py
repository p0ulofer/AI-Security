"""
Classificador de ameaças baseado em XGBoost, rodando em paralelo às heurísticas.

Carrega um modelo treinado (models/xgboost_ids_model.json) e devolve a
probabilidade de ataque (0-1) por IP a partir das features do FEATURE_SCHEMA.
Se o modelo não existir (ou não corresponder ao schema), o sistema continua
funcionando apenas com as heurísticas — score sempre 0.0, sem quebrar.
"""

import logging
import os
from typing import Dict

import numpy as np
import xgboost as xgb

from feature_extractor import FEATURE_SCHEMA

logger = logging.getLogger(__name__)

# Caminho padrão do modelo, relativo a este arquivo (funciona de qualquer CWD)
MODELO_PADRAO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "models", "xgboost_ids_model.json")


class ThreatClassifier:
    """Carrega o modelo XGBoost e expõe score() por IP."""

    def __init__(self, model_path: str = MODELO_PADRAO):
        self.model_path = model_path
        self.model = None
        self._erro_reportado = False
        self._carregar_modelo()

    def _carregar_modelo(self):
        if not os.path.exists(self.model_path):
            logger.warning(
                f"Modelo XGBoost não encontrado em '{self.model_path}'. "
                "Sistema continuará operando apenas com as heurísticas."
            )
            return

        try:
            modelo = xgb.XGBClassifier()
            modelo.load_model(self.model_path)

            # Confere se o modelo foi treinado com o mesmo schema de features
            num_features = modelo.get_booster().num_features()
            if num_features != len(FEATURE_SCHEMA):
                logger.warning(
                    f"Modelo em '{self.model_path}' espera {num_features} features, "
                    f"mas o FEATURE_SCHEMA define {len(FEATURE_SCHEMA)}. "
                    "Provavelmente é o modelo antigo (CICIDS2017); retreine com "
                    "training/gerar_dataset_treino.py + training/treinar_xgboost_ids.py. "
                    "Score do XGBoost ficará em 0.0 até lá."
                )
            else:
                self.model = modelo
                logger.info(
                    f"Modelo XGBoost carregado de '{self.model_path}' "
                    f"({num_features} features)."
                )
        except Exception as e:
            logger.warning(
                f"Falha ao carregar o modelo XGBoost '{self.model_path}': {e}. "
                "Sistema continuará operando apenas com as heurísticas."
            )
            self.model = None

    def score(self, features: Dict[str, float]) -> float:
        """Retorna a probabilidade de ataque (0-1) para as features de um IP.

        Monta o array na ordem exata do FEATURE_SCHEMA. Qualquer problema
        (modelo ausente, contagem de colunas errada, etc.) resulta em 0.0.
        """
        if self.model is None:
            return 0.0

        try:
            x = np.array([[features.get(nome, 0.0) for nome in FEATURE_SCHEMA]],
                         dtype=float)
            probas = self.model.predict_proba(x)[0]

            # Classe 1 = ataque (mesma convenção do treino binário)
            classes = list(getattr(self.model, "classes_", [0, 1]))
            if 1 in classes:
                return float(probas[classes.index(1)])
            return float(probas[-1])
        except Exception as e:
            if not self._erro_reportado:
                logger.warning(
                    f"Erro ao calcular score do XGBoost (será ignorado, retornando 0.0): {e}"
                )
                self._erro_reportado = True
            return 0.0
