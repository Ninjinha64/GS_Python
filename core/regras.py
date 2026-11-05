"""
Motor de regras configurável — reaproveitado do 1º semestre (CP1).

Evoluções para a GS:
- usa os campos estruturados do evento (com fallback para `detalhes`);
- regras com condição desconhecida são ignoradas com aviso;
- o alerta segue o contrato abaixo (compartilhado com API, banco e socket).

Contrato do ALERTA (dict):
    {
        "timestamp": "2025-02-20 08:20:08",
        "regra_id": "R003",
        "regra_nome": "Path Traversal",
        "severidade": "CRITICA" | "ALTA" | "MEDIA" | "BAIXA" | "INFO",
        "ip": "91.240.118.172",
        "fonte": "web",
        "descricao": "...",
        "linha_original": "...",
        "origem": "regra" | "detector" | "manual",
    }
"""
import json
import logging
import os
from typing import Any, Callable, Optional

logger = logging.getLogger("securapy.regras")

SEVERIDADES: tuple[str, ...] = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")


def carregar_regras(caminho_config: str) -> list[dict[str, Any]]:
    """
    Lê o arquivo regras.json e retorna lista de dicionários de regras.
    Trata: arquivo não encontrado, JSON inválido.
    """
    if not os.path.exists(caminho_config):
        logger.error("Arquivo de regras não encontrado: %s", caminho_config)
        return []
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
        regras = dados.get("regras", []) if isinstance(dados, dict) else []
        return [r for r in regras if isinstance(r, dict)]
    except json.JSONDecodeError as e:
        logger.error("JSON inválido em %s: %s", caminho_config, e)
    except OSError as e:
        logger.error("Erro ao carregar regras: %s", e)
    return []


def classificar_severidade(pontuacao: int) -> str:
    """
    Recebe pontuação numérica e retorna string de severidade.
    >= 9: CRITICA, >= 7: ALTA, >= 5: MEDIA, >= 3: BAIXA, < 3: INFO
    """
    if pontuacao >= 9:
        return "CRITICA"
    if pontuacao >= 7:
        return "ALTA"
    if pontuacao >= 5:
        return "MEDIA"
    if pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def _campo_detalhes(evento: dict[str, Any], chave: str) -> str:
    """Lê `chave=valor` do texto `detalhes` (formato da CP1)."""
    detalhes = evento.get("detalhes", "")
    marcador = f"{chave}="
    if marcador not in detalhes:
        return ""
    resto = detalhes.split(marcador, 1)[1].split()
    return resto[0] if resto else ""


def _usuario(evento: dict[str, Any]) -> str:
    return evento.get("usuario") or _campo_detalhes(evento, "usuario")


def _url(evento: dict[str, Any]) -> str:
    return evento.get("url") or _campo_detalhes(evento, "url")


def _porta(evento: dict[str, Any]) -> Optional[int]:
    porta = evento.get("porta")
    if isinstance(porta, int):
        return porta
    texto = _campo_detalhes(evento, "dport")
    return int(texto) if texto.isdigit() else None


# --- Uma função por condição (responsabilidade única) -----------------------

def _cond_usuario_privilegiado(regra: dict[str, Any], evento: dict[str, Any]) -> bool:
    return _usuario(evento) in regra.get("usuarios_alvo", [])


def _cond_porta_critica(regra: dict[str, Any], evento: dict[str, Any]) -> bool:
    return evento.get("tipo") == "BLOCK" and _porta(evento) in regra.get("portas_criticas", [])


def _cond_padroes_url(regra: dict[str, Any], evento: dict[str, Any]) -> bool:
    url = _url(evento).lower()
    return any(p.lower() in url for p in regra.get("padroes", []))


def _cond_reconhecimento(regra: dict[str, Any], evento: dict[str, Any]) -> bool:
    url = _url(evento).lower()
    return any(u.lower() in url for u in regra.get("urls_suspeitas", []))


CONDICOES: dict[str, Callable[[dict[str, Any], dict[str, Any]], bool]] = {
    "usuario_privilegiado": _cond_usuario_privilegiado,
    "porta_critica": _cond_porta_critica,
    "path_traversal": _cond_padroes_url,
    "xss_injection": _cond_padroes_url,
    "reconhecimento": _cond_reconhecimento,
}


def avaliar_regra(regra: dict[str, Any], evento: dict[str, Any]) -> Optional[dict[str, Any]]:
    """
    Avalia se um evento viola uma regra específica.
    Retorna dict de alerta ou None.
    """
    if not regra.get("ativa", False) or regra.get("fonte") != evento.get("fonte"):
        return None

    funcao = CONDICOES.get(regra.get("condicao"))
    if funcao is None:
        logger.warning("Condição desconhecida na regra %s", regra.get("id"))
        return None
    if not funcao(regra, evento):
        return None

    return {
        "timestamp": evento.get("timestamp"),
        "regra_id": regra.get("id"),
        "regra_nome": regra.get("nome"),
        "severidade": classificar_severidade(regra.get("severidade_base", 1)),
        "ip": evento.get("ip"),
        "fonte": evento.get("fonte"),
        "descricao": regra.get("descricao"),
        "linha_original": evento.get("linha_original"),
        "origem": "regra",
    }


def aplicar_regras(eventos: list[dict[str, Any]], regras: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Recebe lista de eventos e lista de regras.
    Retorna lista de alertas gerados.
    """
    alertas: list[dict[str, Any]] = []
    for evento in eventos:
        for regra in regras:
            alerta = avaliar_regra(regra, evento)
            if alerta:
                alertas.append(alerta)
    return alertas
