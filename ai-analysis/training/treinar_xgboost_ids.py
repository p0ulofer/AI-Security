"""
Treinamento do classificador XGBoost para detecção de intrusão de rede,
usando o dataset de tráfego real gerado por gerar_dataset_treino.py.

As features são exatamente as do FEATURE_SCHEMA do feature_extractor.py
(importadas daqui), garantindo a mesma ordem de colunas no treino e na
inferência em tempo real.

Como usar:
    1. Gere o dataset capturando tráfego real (ver gerar_dataset_treino.py):
       sudo python3 gerar_dataset_treino.py --duration 300
    2. Instale as dependências:
       pip install xgboost scikit-learn pandas numpy matplotlib
    3. Rode a partir de training/: python3 treinar_xgboost_ids.py
"""

import os
import sys

# Permite importar os módulos de ../ (pai deste script) — feature_extractor etc.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import joblib

from feature_extractor import FEATURE_SCHEMA

# ----------------------------------------------------------------------
# 1. CONFIGURAÇÃO
# ----------------------------------------------------------------------
CSV_PATH = "dataset_real.csv"                  # gerado por gerar_dataset_treino.py (rode a partir de training/)
LABEL_COLUMN = "label"                         # 0 = normal, 1 = ataque
BINARY = True                                  # True = Normal vs Ataque | False = multiclasse (tipo de ataque)
MODEL_OUT = "../models/xgboost_ids_model.json" # modelo consumido pelo classifier.py em tempo real
ENCODER_OUT = "label_encoder.pkl"

if not os.path.exists(CSV_PATH):
    sys.exit(
        f"Dataset '{CSV_PATH}' não encontrado.\n"
        "Gere-o antes com: sudo python3 gerar_dataset_treino.py --duration 300"
    )

# ----------------------------------------------------------------------
# 2. CARREGAR E LIMPAR OS DADOS
# ----------------------------------------------------------------------
print("Carregando dataset...")
df = pd.read_csv(CSV_PATH, low_memory=False)

# Datasets de rede costumam ter nomes de coluna com espaços/lixo — limpa isso
df.columns = df.columns.str.strip()
if LABEL_COLUMN.strip() != LABEL_COLUMN:
    LABEL_COLUMN = LABEL_COLUMN.strip()

print(f"Formato original: {df.shape}")

# Remove infinitos e NaN, que são comuns em datasets de flow de rede
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
df = df.drop_duplicates()

# Remove colunas totalmente constantes (não ajudam o modelo),
# mas NUNCA as colunas do FEATURE_SCHEMA — o modelo precisa delas na ordem
nunique = df.nunique()
constant_cols = [c for c in nunique[nunique <= 1].index.tolist()
                 if c not in FEATURE_SCHEMA]
df = df.drop(columns=constant_cols)

print(f"Formato após limpeza: {df.shape}")

# ----------------------------------------------------------------------
# 3. PREPARAR LABELS
# ----------------------------------------------------------------------
if BINARY:
    # Normal = 0, qualquer tipo de ataque = 1
    # (aceita tanto 0/1 do dataset real quanto rótulos tipo BENIGN)
    df["target"] = df[LABEL_COLUMN].apply(
        lambda x: 0 if str(x).strip().upper() in ("0", "BENIGN", "NORMAL") else 1
    )
    y = df["target"]
    class_names = ["Normal", "Ataque"]
else:
    # Multiclasse: cada tipo de ataque vira uma classe própria
    encoder = LabelEncoder()
    y = encoder.fit_transform(df[LABEL_COLUMN])
    class_names = list(encoder.classes_)
    joblib.dump(encoder, ENCODER_OUT)

# Features = exatamente o FEATURE_SCHEMA, na mesma ordem da inferência
colunas_ausentes = [c for c in FEATURE_SCHEMA if c not in df.columns]
if colunas_ausentes:
    sys.exit(
        f"Colunas do FEATURE_SCHEMA ausentes no dataset: {colunas_ausentes}\n"
        "Regere o dataset com o gerar_dataset_treino.py atualizado."
    )
X = df[list(FEATURE_SCHEMA)]

print(f"Features usadas: {X.shape[1]}")
print(f"Distribuição das classes:\n{pd.Series(y).value_counts()}")

# ----------------------------------------------------------------------
# 4. SPLIT TREINO / TESTE
# ----------------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ----------------------------------------------------------------------
# 5. TREINAR O XGBOOST
# ----------------------------------------------------------------------
print("Treinando XGBoost...")

# scale_pos_weight ajuda quando as classes são desbalanceadas
# (tráfego malicioso costuma ser bem mais raro que o normal)
if BINARY:
    neg, pos = np.bincount(y_train)
    scale_pos_weight = neg / pos
else:
    scale_pos_weight = 1

model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic" if BINARY else "multi:softprob",
    eval_metric="logloss",
    scale_pos_weight=scale_pos_weight,
    tree_method="hist",     # rápido mesmo em CPU
    random_state=42,
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=False,
)

# ----------------------------------------------------------------------
# 6. AVALIAR
# ----------------------------------------------------------------------
y_pred = model.predict(X_test)

print("\n=== Relatório de Classificação ===")
print(classification_report(y_test, y_pred, target_names=class_names))

cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
disp.plot(cmap="Blues", values_format="d")
plt.title("Matriz de Confusão - XGBoost IDS")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
print("\nMatriz de confusão salva em confusion_matrix.png")

# ----------------------------------------------------------------------
# 7. FEATURE IMPORTANCE (quais campos mais pesam na decisão)
# ----------------------------------------------------------------------
importances = pd.Series(model.feature_importances_, index=X.columns)
importances = importances.sort_values(ascending=False).head(15)

plt.figure(figsize=(8, 6))
importances.plot(kind="barh")
plt.gca().invert_yaxis()
plt.title("Top 15 features mais importantes")
plt.tight_layout()
plt.savefig("feature_importance.png")
print("Importância das features salva em feature_importance.png")

# ----------------------------------------------------------------------
# 8. SALVAR O MODELO
# ----------------------------------------------------------------------
model.save_model(MODEL_OUT)
print(f"\nModelo salvo em {MODEL_OUT}")

# ----------------------------------------------------------------------
# 9. EXEMPLO DE COMO USAR O MODELO DEPOIS (inferência)
# ----------------------------------------------------------------------
# loaded_model = xgb.XGBClassifier()
# loaded_model.load_model(MODEL_OUT)
# proba = loaded_model.predict_proba(novo_evento_df)[:, 1]  # probabilidade de ser ataque
# score_severidade = round(proba[0] * 10, 1)  # transforma em score 1-10 pra passar pro LLM
