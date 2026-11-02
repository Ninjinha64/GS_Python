"""
Orquestração do pipeline (núcleo 1º sem + camadas do 2º sem).

    eventos → regras → detector → ML (score + anomalias) → MongoDB → socket

É chamada pela API (`POST /api/analisar`), pelo dashboard e pela migração.
Nenhuma rota fala direto com o núcleo — tudo passa por aqui (camada de serviço).
"""
import json
import logging
import os
from datetime import datetime

import settings
from alertas import publicador
from core import coletor, detector, enriquecimento, regras
from ia import assistente
from ml import classificar

logger = logging.getLogger("securapy.servicos")


class EntradaInvalidaError(ValueError):
    """Dados de entrada do pipeline inválidos (vira 400 na API)."""


# ------------------------------------------------------------ entrada
def resolver_caminho_log(caminho):
    """
    Aceita apenas caminhos DENTRO da pasta de logs configurada.
    Bloqueia path traversal (ex.: "../../etc/passwd") — afinal, isto é uma
    ferramenta de segurança.
    """
    if not isinstance(caminho, str) or not caminho.strip() or "\x00" in caminho:
        raise EntradaInvalidaError("caminho inválido")
    base = os.path.realpath(settings.PASTA_LOGS)
    relativo = caminho.strip()
    if relativo in ("logs", "logs/", "logs\\"):
        relativo = "."
    elif relativo.startswith(("logs/", "logs\\")):
        relativo = relativo[5:]
    alvo = os.path.realpath(os.path.join(base, relativo))
    if os.path.commonpath([base, alvo]) != base:
        raise EntradaInvalidaError("caminho fora da pasta de logs permitida")
    if not os.path.exists(alvo):
        raise EntradaInvalidaError("arquivo ou pasta de log não encontrado")
    return alvo


def carregar_de_caminho(caminho):
    alvo = resolver_caminho_log(caminho)
    if os.path.isdir(alvo):
        return coletor.carregar_todos_os_logs(alvo)
    fonte = coletor.identificar_fonte(os.path.basename(alvo))
    if not fonte:
        raise EntradaInvalidaError("não foi possível identificar a fonte pelo nome do arquivo")
    return coletor.carregar_log(alvo, fonte)


def carregar_de_lote(lote):
    """
    Lote aceito em dois formatos:
      [{"fonte": "auth", "linha": "2025-02-20 08:15:01 FAIL usuario=x ip=1.2.3.4"}, ...]
      {"fonte": "auth", "linhas": ["...", "..."]}
    As linhas passam pelo MESMO parser do coletor (nada de confiar em
    eventos já "prontos" vindos do cliente).
    """
    if isinstance(lote, dict):
        lote = [{"fonte": lote.get("fonte"), "linha": l} for l in (lote.get("linhas") or [])]
    if not isinstance(lote, list) or not lote:
        raise EntradaInvalidaError("lote deve ser uma lista não vazia")
    if len(lote) > 5000:
        raise EntradaInvalidaError("lote excede 5000 linhas")

    por_fonte = {}
    for item in lote:
        if not isinstance(item, dict):
            raise EntradaInvalidaError("cada item do lote deve ser um objeto")
        fonte, linha = item.get("fonte"), item.get("linha")
        if fonte not in coletor.FONTES_VALIDAS:
            raise EntradaInvalidaError(f"fonte inválida (use {', '.join(coletor.FONTES_VALIDAS)})")
        if not isinstance(linha, str) or len(linha) > 2000:
            raise EntradaInvalidaError("linha ausente ou muito longa")
        por_fonte.setdefault(fonte, []).append(linha)

    eventos = []
    for fonte, linhas in por_fonte.items():
        evs, _ = coletor.parsear_linhas(linhas, fonte, origem="lote-api")
        eventos.extend(e for e in evs if enriquecimento.ip_valido(e["ip"]))
    return eventos


# ------------------------------------------------------------ pipeline
def analisar_eventos(repo, eventos, notificar=True):
    """Roda regras + detector + ML, persiste e publica. Retorna resumo (dict)."""
    lista_regras = regras.carregar_regras(settings.ARQUIVO_REGRAS)
    blacklist = settings.BLACKLIST

    # 1º semestre — motor de regras e detector
    alertas_regras = regras.aplicar_regras(eventos, lista_regras)
    bf = detector.detectar_brute_force(eventos)
    ps = detector.detectar_port_scan(eventos)
    bl_ips, bl_cont = detector.verificar_blacklist(eventos, blacklist)
    janela = detector.detectar_brute_force_janela(eventos, janela_segundos=60)
    resumo_ameacas = detector.gerar_resumo_ameacas(bf, ps, bl_ips, bl_cont)
    alertas = alertas_regras + detector.alertas_do_detector(bf, ps, bl_ips, janela)

    # 2º semestre — ML (score de risco) + Isolation Forest (bônus)
    scores, feats, status_ml = classificar.pontuar_com_seguranca(eventos, blacklist, lista_regras)
    anomalias = {}
    try:
        from ml.anomalias import detectar_anomalias
        anomalias = detectar_anomalias(feats)
    except Exception as e:  # bônus nunca derruba o pipeline
        logger.warning("Detecção de anomalias indisponível: %s", type(e).__name__)

    deteccoes = {a["ip"]: a for a in resumo_ameacas}
    ameacas = []
    for ip, f in feats.items():
        det = deteccoes.get(ip, {})
        ml = scores.get(ip, {})
        ameacas.append({
            "ip": ip, "features": f,
            "motivos": det.get("motivos", ""), "pontuacao": det.get("pontuacao", 0),
            "severidade_final": det.get("severidade_final", "INFO"),
            "score_ml": ml.get("score", 0.0), "rotulo_ml": ml.get("rotulo"), "nivel_ml": ml.get("nivel"),
            "anomalia": anomalias.get(ip, {}),
            "janela_temporal": janela.get(ip),
        })

    # persistência (Módulo B)
    score_por_ip = {ip: s["score"] for ip, s in scores.items()}
    res_eventos = repo.salvar_eventos(eventos)
    res_alertas = repo.salvar_alertas(alertas, score_por_ip)
    repo.salvar_ameacas(ameacas)

    # tempo real (1º sem) — priorizados pelo score do ML
    enviados = 0
    if notificar:
        for a in alertas:
            a["score_risco"] = score_por_ip.get(a.get("ip"), 0.0)
        alertas_ordenados = sorted(alertas, key=lambda a: a["score_risco"], reverse=True)
        enviados = publicador.publicar(alertas_ordenados)

    por_fonte = {}
    for e in eventos:
        por_fonte[e["fonte"]] = por_fonte.get(e["fonte"], 0) + 1
    top = sorted(ameacas, key=lambda a: (a["score_ml"], a["pontuacao"]), reverse=True)[:10]

    return {
        "eventos_processados": len(eventos),
        "eventos_por_fonte": por_fonte,
        "eventos_novos": res_eventos["novos"],
        "alertas_gerados": len(alertas),
        "alertas_regras": len(alertas_regras),
        "alertas_detector": len(alertas) - len(alertas_regras),
        "alertas_novos": res_alertas["novos"],
        "brute_force": bf,
        "port_scan": ps,
        "blacklist": sorted(bl_ips),
        "ml_status": status_ml,
        "top_ips_risco": [{"ip": a["ip"], "score_ml": a["score_ml"], "rotulo_ml": a["rotulo_ml"],
                           "motivos": a["motivos"], "anomalo": a["anomalia"].get("anomalo")} for a in top],
        "alertas_notificados_socket": enviados,
    }


def analisar_logs_padrao(repo, notificar=True):
    """Atalho: analisa a pasta de logs configurada."""
    return analisar_eventos(repo, coletor.carregar_todos_os_logs(settings.PASTA_LOGS), notificar)


# ------------------------------------------------------------ consultas
_cache_explicacoes = {}


def explicar_ip(alertas):
    """Explicação do assistente LLM para o alerta mais prioritário do IP (com cache)."""
    if not alertas:
        return None
    alvo = max(alertas, key=lambda a: (a.get("sev_nivel", 0), a.get("score_risco", 0)))
    chave = alvo.get("id")
    if chave not in _cache_explicacoes:
        _cache_explicacoes[chave] = assistente.classificar(alvo)
    return dict(_cache_explicacoes[chave], alerta_id=chave)


def info_ip(repo, ip, max_eventos=200):
    """Visão 360° de um IP: eventos, alertas, geolocalização, score de ML e explicação do LLM."""
    eventos, total_ev = repo.buscar_eventos(ip=ip, pagina=1, tamanho=max_eventos)
    alertas, total_al = repo.buscar_alertas(ip=ip, pagina=1, tamanho=100)
    ameaca = repo.obter_ameaca(ip) or {}
    return {
        "ip": ip,
        "encontrado": bool(total_ev or total_al),
        "privado": enriquecimento.eh_ip_privado(ip),
        "na_blacklist": ip in settings.BLACKLIST,
        "total_eventos": total_ev,
        "eventos": eventos,
        "total_alertas": total_al,
        "alertas": alertas,
        "geolocalizacao": enriquecimento.consultar_ip(ip),
        "ml": {
            "score": ameaca.get("score_ml"), "rotulo": ameaca.get("rotulo_ml"),
            "nivel": ameaca.get("nivel_ml"), "features": ameaca.get("features"),
            "anomalia": ameaca.get("anomalia"),
        },
        "deteccoes": {"motivos": ameaca.get("motivos"), "severidade": ameaca.get("severidade_final"),
                      "janela_temporal": ameaca.get("janela_temporal")},
        "assistente": explicar_ip(alertas),
    }


def montar_relatorio(repo):
    """Relatório completo (entregável 4) como dict."""
    alertas, _ = repo.buscar_alertas(pagina=1, tamanho=1000)
    return {
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "plataforma": "SecuraPy Platform",
        "resumo": repo.resumo(),
        "top_ips_eventos": repo.top_ips(10),
        "ameacas_priorizadas_ml": repo.listar_ameacas(20),
        "alertas_priorizados": alertas,
    }


def exportar_relatorio(repo, pasta=None):
    """Salva o relatório em saida/relatorio_<data>.json e retorna o caminho."""
    pasta = pasta or settings.PASTA_SAIDA
    os.makedirs(pasta, exist_ok=True)
    caminho = os.path.join(pasta, f"relatorio_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(montar_relatorio(repo), f, indent=2, ensure_ascii=False, default=str)
    return caminho
