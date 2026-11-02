"""
BÔNUS — Detecção de anomalias com Isolation Forest (Módulo C, item 4).

As regras e o classificador só reconhecem o que já conhecem. O Isolation
Forest aprende o "normal" (perfis sintéticos de tráfego legítimo) e marca
como anômalo qualquer IP cujo comportamento fuja desse padrão — inclusive
padrões de ataque que ninguém escreveu regra.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features import vetor
from ml.treinar import SEMENTE, dataset_sintetico

_modelo = {}


def treinar_detector_anomalias(contaminacao=0.02):
    """Treina sobre perfis NORMAIS sintéticos (linha de base)."""
    X, y = dataset_sintetico()
    normais = X[y == 0]
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(n_estimators=200, contamination=contaminacao, random_state=SEMENTE)),
    ])
    pipeline.fit(normais)
    return pipeline


def obter_detector():
    if "pipeline" not in _modelo:
        _modelo["pipeline"] = treinar_detector_anomalias()
    return _modelo["pipeline"]


def detectar_anomalias(features_por_ip):
    """
    Retorna {ip: {"anomalo": bool, "score_anomalia": float}}.
    score_anomalia > 0 = mais anômalo (invertemos o decision_function).
    """
    if not features_por_ip:
        return {}
    pipeline = obter_detector()
    ips = list(features_por_ip)
    X = np.array([vetor(features_por_ip[ip]) for ip in ips])
    predicoes = pipeline.predict(X)                 # -1 = anomalia, 1 = normal
    scores = -pipeline.decision_function(X)
    return {
        ip: {"anomalo": bool(p == -1), "score_anomalia": round(float(s), 4)}
        for ip, p, s in zip(ips, predicoes, scores)
    }
