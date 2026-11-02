"""
Classificação / priorização de risco (Módulo C).

Carrega o modelo SOMENTE se o hash SHA-256 conferir, e atribui a cada IP um
score de risco (probabilidade de "ataque"), usado para ordenar os alertas.
"""
import logging
import os
import threading

import joblib

from ml.features import extrair_features, vetor
from ml.integridade import ModeloAdulteradoError, verificar_integridade

logger = logging.getLogger("securapy.ml.classificar")

PASTA_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.path.join(PASTA_ML, "modelo.pkl")
CAMINHO_HASH = os.path.join(PASTA_ML, "modelo.sha256")

LIMIAR_ATAQUE = 0.5
NIVEIS = ((0.75, "ALTO"), (0.4, "MEDIO"), (0.0, "BAIXO"))  # tuplas imutáveis

_cache = {}
_lock = threading.Lock()


class ModeloIndisponivelError(Exception):
    """Modelo não treinado ainda (rode `python -m ml.treinar`)."""


def carregar_modelo(caminho=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH, usar_cache=True):
    """
    Verifica a integridade e carrega o modelo. Lança:
      - ModeloIndisponivelError se o arquivo não existe;
      - ModeloAdulteradoError se o hash não confere (NÃO carrega o pickle).
    """
    if not os.path.isfile(caminho):
        raise ModeloIndisponivelError("modelo não encontrado — rode `python -m ml.treinar`")

    digest = verificar_integridade(caminho, caminho_hash)  # antes do joblib.load!
    with _lock:
        if usar_cache and _cache.get("digest") == digest:
            return _cache["modelo"]
        modelo = joblib.load(caminho)
        _cache.update(digest=digest, modelo=modelo)
    logger.info("Modelo carregado (sha256=%s…)", digest[:12])
    return modelo


def nivel_risco(score):
    for limite, nome in NIVEIS:
        if score >= limite:
            return nome
    return "BAIXO"


def pontuar_features(features_por_ip, modelo=None):
    """
    Recebe {ip: {feature: valor}} e retorna
    {ip: {"score": 0..1, "rotulo": "ataque"|"normal", "nivel": "ALTO"|"MEDIO"|"BAIXO"}}.
    """
    if not features_por_ip:
        return {}
    modelo = modelo or carregar_modelo()
    pipeline, ordem = modelo["pipeline"], modelo["features"]
    ips = list(features_por_ip)
    probabilidades = pipeline.predict_proba([vetor(features_por_ip[ip], ordem) for ip in ips])[:, 1]
    return {
        ip: {
            "score": round(float(p), 4),
            "rotulo": "ataque" if p >= LIMIAR_ATAQUE else "normal",
            "nivel": nivel_risco(float(p)),
        }
        for ip, p in zip(ips, probabilidades)
    }


def pontuar(eventos, blacklist=frozenset(), regras=None, modelo=None):
    """Atalho: eventos → features → scores. Retorna (scores, features)."""
    feats = extrair_features(eventos, blacklist, regras)
    return pontuar_features(feats, modelo), feats


def pontuar_com_seguranca(eventos, blacklist=frozenset(), regras=None):
    """
    Versão tolerante a falhas usada pela API: se o modelo estiver ausente
    ou ADULTERADO, registra o alerta e devolve scores vazios (a plataforma
    continua funcionando só com regras). Retorna (scores, features, status).
    """
    feats = extrair_features(eventos, blacklist, regras)
    try:
        return pontuar_features(feats), feats, "ok"
    except ModeloAdulteradoError as e:
        logger.critical("ALERTA DE INTEGRIDADE: modelo de ML adulterado — %s", e)
        return {}, feats, "modelo_adulterado"
    except ModeloIndisponivelError as e:
        logger.warning("%s", e)
        return {}, feats, "modelo_indisponivel"
