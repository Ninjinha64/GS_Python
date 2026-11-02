"""
Treino do classificador de risco (Módulo C — Aulas 4 e 12).

Uso:  python -m ml.treinar

Dataset:
  1. IPs REAIS dos logs de teste → features via `ml.features` e rótulo dado
     pelo detector do 1º semestre (IP com brute force / port scan / blacklist
     = "ataque"; demais = "normal").
  2. Como os logs têm só ~8 IPs, somamos perfis SINTÉTICOS (semente fixa →
     reproduzível) de tráfego normal e de 3 famílias de ataque (brute force,
     port scan, ataque web), com sobreposição e ruído de rótulo para o modelo
     não "decorar" um limiar trivial.

Modelo: Pipeline(StandardScaler → RandomForestClassifier), avaliado com
validação cruzada estratificada (5 folds) — precisão, recall, F1 e acurácia.

Saídas (em ml/):
  modelo.pkl      — pipeline + metadados (joblib)
  modelo.sha256   — hash de integridade
  metricas.json   — relatório de métricas
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import settings  # noqa: E402
from core import coletor, detector, regras  # noqa: E402
from ml.features import FEATURES, extrair_features, vetor  # noqa: E402
from ml.integridade import registrar_hash  # noqa: E402

logger = logging.getLogger("securapy.ml.treinar")

PASTA_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.path.join(PASTA_ML, "modelo.pkl")
CAMINHO_HASH = os.path.join(PASTA_ML, "modelo.sha256")
CAMINHO_METRICAS = os.path.join(PASTA_ML, "metricas.json")
SEMENTE = 42
ROTULOS = ("normal", "ataque")  # 0, 1


# ----------------------------------------------------------------- dados
def dataset_real(eventos, blacklist, lista_regras):
    """Features + rótulo (pelo detector) dos IPs reais dos logs."""
    feats = extrair_features(eventos, blacklist, lista_regras)
    bf = detector.detectar_brute_force(eventos)
    ps = detector.detectar_port_scan(eventos)
    bl, _ = detector.verificar_blacklist(eventos, blacklist)
    maliciosos = set(bf) | set(ps) | bl
    X = [vetor(f) for f in feats.values()]
    y = [1 if ip in maliciosos else 0 for ip in feats]
    return X, y, list(feats)


def _perfil(rng, fails, ok, portas, web_total, taxa_erro, alertas, p_blacklist):
    """Gera um vetor de features sorteando cada métrica dentro de um intervalo."""
    portas_d = int(rng.integers(*portas))
    web_t = int(rng.integers(*web_total))
    return [
        int(rng.integers(*fails)),
        int(rng.integers(*ok)),
        portas_d,
        portas_d + int(rng.integers(0, 4)),               # bloqueios >= portas distintas
        int(round(web_t * rng.uniform(*taxa_erro))),
        web_t,
        int(rng.integers(*alertas)),
        int(rng.random() < p_blacklist),
    ]


def dataset_sintetico(n_normal=400, n_ataque=300, ruido=0.03, semente=SEMENTE):
    """Perfis sintéticos rotulados. Intervalos com sobreposição proposital."""
    rng = np.random.default_rng(semente)
    X, y = [], []
    for _ in range(n_normal):
        X.append(_perfil(rng, (0, 4), (0, 6), (0, 3), (0, 40), (0.0, 0.25), (0, 2), 0.02))
        y.append(0)
    familias = (
        # fails     ok      portas    web       erro         alertas  blacklist
        ((4, 45), (0, 3), (0, 3), (0, 6), (0.0, 0.5), (1, 15), 0.45),   # brute force
        ((0, 3), (0, 2), (3, 40), (0, 6), (0.0, 0.5), (1, 12), 0.45),   # port scan
        ((0, 4), (0, 2), (0, 3), (4, 60), (0.4, 1.0), (2, 12), 0.40),   # ataque web
    )
    for i in range(n_ataque):
        X.append(_perfil(rng, *familias[i % len(familias)]))
        y.append(1)
    y = np.array(y)
    trocar = rng.random(len(y)) < ruido   # ruído de rótulo
    y[trocar] = 1 - y[trocar]
    return np.array(X, dtype=float), y


def criar_pipeline():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("modelo", RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced", random_state=SEMENTE)),
    ])


# ----------------------------------------------------------------- treino
def treinar(pasta_logs=None, caminho_regras=None, salvar=True, verbose=True):
    """Treina, avalia e (opcionalmente) persiste o modelo. Retorna dict de métricas."""
    eventos = coletor.carregar_todos_os_logs(pasta_logs or settings.PASTA_LOGS)
    lista_regras = regras.carregar_regras(caminho_regras or settings.ARQUIVO_REGRAS)
    Xr, yr, ips_reais = dataset_real(eventos, settings.BLACKLIST, lista_regras)
    Xs, ys = dataset_sintetico()

    X = np.vstack([Xs, np.array(Xr, dtype=float)]) if Xr else Xs
    y = np.concatenate([ys, np.array(yr)]) if yr else ys

    # 1) validação cruzada estratificada
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEMENTE)
    cv_res = cross_validate(criar_pipeline(), X, y, cv=cv,
                            scoring=("precision", "recall", "f1", "accuracy"))
    resumo_cv = {m: {"media": round(float(np.mean(cv_res[f"test_{m}"])), 4),
                     "desvio": round(float(np.std(cv_res[f"test_{m}"])), 4)}
                 for m in ("precision", "recall", "f1", "accuracy")}

    # 2) hold-out para relatório por classe
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=SEMENTE)
    holdout = criar_pipeline().fit(X_tr, y_tr)
    relatorio = classification_report(y_te, holdout.predict(X_te), target_names=ROTULOS,
                                      output_dict=True, zero_division=0)
    relatorio_txt = classification_report(y_te, holdout.predict(X_te), target_names=ROTULOS,
                                          zero_division=0)

    # 3) modelo final com todos os dados
    pipeline = criar_pipeline().fit(X, y)
    importancias = dict(zip(FEATURES, (round(float(v), 4) for v in
                                       pipeline.named_steps["modelo"].feature_importances_)))

    metricas = {
        "treinado_em": datetime.now(timezone.utc).isoformat(),
        "amostras": {"total": int(len(y)), "ataque": int(y.sum()), "normal": int(len(y) - y.sum()),
                     "reais": len(ips_reais), "sinteticas": int(len(ys))},
        "features": list(FEATURES),
        "validacao_cruzada_5fold": resumo_cv,
        "holdout_25pct": {k: v for k, v in relatorio.items() if k in ROTULOS or k == "accuracy"},
        "importancia_features": importancias,
    }

    if salvar:
        joblib.dump({"pipeline": pipeline, "features": list(FEATURES), "rotulos": list(ROTULOS),
                     "versao": metricas["treinado_em"]}, CAMINHO_MODELO)
        metricas["sha256"] = registrar_hash(CAMINHO_MODELO, CAMINHO_HASH)
        with open(CAMINHO_METRICAS, "w", encoding="utf-8") as f:
            json.dump(metricas, f, indent=2, ensure_ascii=False)

    if verbose:
        print("=" * 60)
        print(" SecuraPy — Treino do classificador de risco")
        print("=" * 60)
        print(f"Amostras: {metricas['amostras']}")
        print("\nValidação cruzada (5 folds):")
        for nome, v in resumo_cv.items():
            print(f"  {nome:<10} {v['media']:.4f} ± {v['desvio']:.4f}")
        print("\nHold-out (25%):")
        print(relatorio_txt)
        print("Importância das features:")
        for nome, v in sorted(importancias.items(), key=lambda kv: -kv[1]):
            print(f"  {nome:<18} {v:.4f}")
        if salvar:
            print(f"\nModelo salvo em: {CAMINHO_MODELO}")
            print(f"SHA-256:         {metricas['sha256']}")
            print(f"Métricas em:     {CAMINHO_METRICAS}")
    return metricas


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    treinar()
