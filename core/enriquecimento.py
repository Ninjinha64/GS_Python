"""
Enriquecimento de IPs (Threat Intelligence) — reaproveitado do 1º semestre.

Evoluções para a GS:
- validação/classificação de IP com o módulo `ipaddress` (substitui o split
  manual da CP1 e serve também para validar entrada da API);
- cache em dict com TTL e lock (a API é multi-thread);
- token opcional do ipinfo.io via variável de ambiente IPINFO_TOKEN;
- modo offline (SECURAPY_OFFLINE=1) para demo/testes sem internet;
- erros de rede tratados — nunca derrubam a chamada.
"""
import ipaddress
import logging
import os
import threading
import time
from typing import Any, Optional

import requests

logger = logging.getLogger("securapy.enriquecimento")

TTL_CACHE_S: int = 3600
_cache_global: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def ip_valido(ip: Any) -> bool:
    """True se `ip` é um IPv4/IPv6 válido."""
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def eh_ip_privado(ip: Any) -> bool:
    """
    Verifica se um IP é de rede privada (RFC 1918), loopback ou link-local.
    Retorna False para IPs inválidos.
    """
    try:
        obj = ipaddress.ip_address(str(ip))
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False


def _consultar_ipinfo(ip: str) -> dict[str, Any]:
    """Faz a chamada HTTP ao ipinfo.io. Retorna dict normalizado (ou com 'erro')."""
    if os.getenv("SECURAPY_OFFLINE") == "1":
        return {"ip": ip, "erro": "Modo offline (enriquecimento desativado)"}

    params: dict[str, str] = {}
    token = os.getenv("IPINFO_TOKEN")
    if token:
        params["token"] = token
    try:
        resposta = requests.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=5)
    except requests.exceptions.Timeout:
        return {"ip": ip, "erro": "Timeout na consulta"}
    except requests.exceptions.RequestException:
        return {"ip": ip, "erro": "Erro de rede/API indisponível"}

    if resposta.status_code == 429:
        return {"ip": ip, "erro": "Limite de requisições excedido"}
    if resposta.status_code != 200:
        return {"ip": ip, "erro": f"Status {resposta.status_code}"}
    try:
        dados = resposta.json()
    except ValueError:
        return {"ip": ip, "erro": "Resposta inválida da API"}

    return {
        "ip": ip,
        "cidade": dados.get("city", "Desconhecida"),
        "regiao": dados.get("region", "Desconhecida"),
        "pais": dados.get("country", "Desconhecido"),
        "org": dados.get("org", "Desconhecida"),
        "hostname": dados.get("hostname", "-"),
        "loc": dados.get("loc"),
    }


def consultar_ip(ip: str, cache: Optional[dict[str, dict[str, Any]]] = None) -> dict[str, Any]:
    """
    Consulta ipinfo.io para obter dados do IP.
    Usa cache (dict) para evitar consultas repetidas.
    Retorna dict com: ip, cidade, regiao, pais, org, hostname (ou 'erro').
    """
    cache = _cache_global if cache is None else cache
    agora = time.time()
    with _lock:
        item = cache.get(ip)
        if item and agora - item.get("_em", agora) < TTL_CACHE_S:
            return {k: v for k, v in item.items() if k != "_em"}

    if not ip_valido(ip):
        return {"ip": ip, "erro": "IP inválido"}

    if eh_ip_privado(ip):
        resultado: dict[str, Any] = {
            "ip": ip, "cidade": "-", "regiao": "-", "pais": "Rede Interna",
            "org": "Local", "hostname": "-",
        }
    else:
        resultado = _consultar_ipinfo(ip)

    # erros não são cacheados por muito tempo: só sucesso entra no cache
    if "erro" not in resultado:
        with _lock:
            cache[ip] = dict(resultado, _em=agora)
    return resultado


def enriquecer_alertas(
    alertas: list[dict[str, Any]],
    cache: Optional[dict[str, dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """
    Recebe lista de alertas e adiciona informações de geolocalização.
    Retorna NOVA lista (não altera a original).
    """
    enriquecidos: list[dict[str, Any]] = []
    for alerta in alertas:
        novo = dict(alerta)
        if alerta.get("ip"):
            novo["inteligencia"] = consultar_ip(alerta["ip"], cache)
        enriquecidos.append(novo)
    return enriquecidos
