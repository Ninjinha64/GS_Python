"""
Detector de ameaças — reaproveitado do 1º semestre (CP1).

Mantém brute force (dict de contagem + set de usuários), port scan
(set de portas por IP) e blacklist (interseção de sets).

Evoluções para a GS:
- BÔNUS: correlação temporal (`detectar_brute_force_janela`): brute force
  dentro de uma janela deslizante de tempo, não só contagem total;
- `alertas_do_detector`: converte as detecções no contrato de ALERTA;
- `except:` genérico trocado por exceções específicas.
"""
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from core.regras import classificar_severidade

FORMATO_TS: str = "%Y-%m-%d %H:%M:%S"

# Blacklist de Threat Intelligence (set → busca O(1) e operações de conjunto)
BLACKLIST_PADRAO: frozenset[str] = frozenset({"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"})

PESOS_SEVERIDADE: dict[str, int] = {"MEDIA": 5, "ALTA": 7, "CRITICA": 9}


def _severidade_por_volume(qtd: int, limite_alta: int, limite_critica: int) -> str:
    if qtd > limite_critica:
        return "CRITICA"
    if qtd > limite_alta:
        return "ALTA"
    return "MEDIA"


def detectar_brute_force(eventos: list[dict[str, Any]], threshold: int = 5) -> dict[str, dict[str, Any]]:
    """
    Conta tentativas FAIL por IP nos eventos de auth.
    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """
    contagem: dict[str, dict[str, Any]] = {}
    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            usuario = evento.get("usuario") or "desconhecido"
            dados = contagem.setdefault(ip, {"tentativas": 0, "usuarios": set()})
            dados["tentativas"] += 1
            dados["usuarios"].add(usuario)

    resultados: dict[str, dict[str, Any]] = {}
    for ip, dados in contagem.items():
        if dados["tentativas"] >= threshold:
            resultados[ip] = {
                "tentativas": dados["tentativas"],
                "usuarios": sorted(dados["usuarios"]),
                "severidade": _severidade_por_volume(dados["tentativas"], 10, 20),
                "motivo": "Brute Force",
            }
    return resultados


def detectar_brute_force_janela(
    eventos: list[dict[str, Any]],
    janela_segundos: int = 60,
    threshold: int = 5,
) -> dict[str, dict[str, Any]]:
    """
    BÔNUS — correlação temporal.
    Para cada IP, desliza uma janela de `janela_segundos` sobre os FAILs
    ordenados por tempo e registra o pico de tentativas dentro da janela.
    Retorna dict: {ip: {"pico": N, "janela_s": S, "inicio": ts, "fim": ts}}
    """
    por_ip: dict[str, list[datetime]] = {}
    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            try:
                ts = datetime.strptime(evento.get("timestamp", ""), FORMATO_TS)
            except ValueError:
                continue
            por_ip.setdefault(evento.get("ip"), []).append(ts)

    janela = timedelta(seconds=janela_segundos)
    resultados: dict[str, dict[str, Any]] = {}
    for ip, tempos in por_ip.items():
        tempos.sort()
        fila: deque[datetime] = deque()
        melhor: tuple[int, Optional[datetime], Optional[datetime]] = (0, None, None)
        for ts in tempos:
            fila.append(ts)
            while ts - fila[0] > janela:
                fila.popleft()
            if len(fila) > melhor[0]:
                melhor = (len(fila), fila[0], ts)
        if melhor[0] >= threshold and melhor[1] is not None and melhor[2] is not None:
            resultados[ip] = {
                "pico": melhor[0],
                "janela_s": janela_segundos,
                "inicio": melhor[1].strftime(FORMATO_TS),
                "fim": melhor[2].strftime(FORMATO_TS),
                "motivo": "Brute Force (janela temporal)",
            }
    return resultados


def detectar_port_scan(eventos: list[dict[str, Any]], threshold: int = 3) -> dict[str, dict[str, Any]]:
    """
    Conta portas únicas (BLOCK) por IP nos eventos de firewall.
    Retorna dict: {ip: {"portas": [...], "quantidade": N, "severidade": "..."}}
    """
    contagem: dict[str, set[int]] = {}
    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            porta = evento.get("porta")
            if porta is None:
                try:
                    porta = int(evento.get("detalhes", "").split("dport=")[-1].split()[0])
                except (ValueError, IndexError):
                    continue
            contagem.setdefault(evento.get("ip"), set()).add(porta)

    resultados: dict[str, dict[str, Any]] = {}
    for ip, portas in contagem.items():
        if len(portas) >= threshold:
            resultados[ip] = {
                "portas": sorted(portas),
                "quantidade": len(portas),
                "severidade": _severidade_por_volume(len(portas), 5, 10),
                "motivo": "Port Scan",
            }
    return resultados


def verificar_blacklist(
    eventos: list[dict[str, Any]],
    blacklist: Iterable[str] = BLACKLIST_PADRAO,
) -> tuple[set[str], dict[str, int]]:
    """
    Cruza IPs dos eventos com a blacklist usando operações de set.
    Retorna set de IPs maliciosos encontrados e dict com contagem por IP.
    """
    ips_eventos = {e.get("ip") for e in eventos if e.get("ip")}
    ips_encontrados = ips_eventos & set(blacklist)

    contagem = {ip: 0 for ip in ips_encontrados}
    for evento in eventos:
        if evento.get("ip") in contagem:
            contagem[evento["ip"]] += 1
    return ips_encontrados, contagem


def gerar_resumo_ameacas(
    brute_force: dict[str, dict[str, Any]],
    port_scan: dict[str, dict[str, Any]],
    ips_blacklist: Iterable[str],
    contagem_blacklist: dict[str, int],
) -> list[dict[str, Any]]:
    """
    Consolida todas as detecções em um resumo unificado.
    IPs que aparecem em múltiplas detecções têm severidade aumentada.
    Retorna lista de dicts ordenada por pontuação.
    """
    resumo: dict[str, dict[str, Any]] = {}

    def acumular(ip: str, motivo: str, pontos: int) -> None:
        item = resumo.setdefault(ip, {"motivos": [], "pontuacao": 0})
        item["motivos"].append(motivo)
        item["pontuacao"] += pontos

    for ip, dados in brute_force.items():
        acumular(ip, dados["motivo"], PESOS_SEVERIDADE[dados["severidade"]])
    for ip, dados in port_scan.items():
        acumular(ip, dados["motivo"], PESOS_SEVERIDADE[dados["severidade"]])
    for ip in ips_blacklist:
        acumular(ip, "IP em Blacklist", 8)

    lista_resumo = [
        {
            "ip": ip,
            "motivos": " + ".join(dados["motivos"]),
            "pontuacao": dados["pontuacao"],
            "severidade_final": classificar_severidade(dados["pontuacao"]),
            "eventos_ip": contagem_blacklist.get(ip),
        }
        for ip, dados in resumo.items()
    ]
    lista_resumo.sort(key=lambda x: x["pontuacao"], reverse=True)
    return lista_resumo


def alertas_do_detector(
    brute_force: dict[str, dict[str, Any]],
    port_scan: dict[str, dict[str, Any]],
    ips_blacklist: Iterable[str],
    janela: Optional[dict[str, dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Converte as detecções do detector em alertas (mesmo contrato do motor de regras)."""
    alertas: list[dict[str, Any]] = []
    for ip, d in brute_force.items():
        alertas.append({
            "timestamp": None, "regra_id": "D001", "regra_nome": "Brute Force",
            "severidade": d["severidade"], "ip": ip, "fonte": "auth",
            "descricao": f"{d['tentativas']} falhas de login (usuários: {', '.join(d['usuarios'])})",
            "linha_original": None, "origem": "detector",
        })
    for ip, d in port_scan.items():
        alertas.append({
            "timestamp": None, "regra_id": "D002", "regra_nome": "Port Scan",
            "severidade": d["severidade"], "ip": ip, "fonte": "firewall",
            "descricao": f"{d['quantidade']} portas distintas bloqueadas: {d['portas']}",
            "linha_original": None, "origem": "detector",
        })
    for ip in sorted(ips_blacklist):
        alertas.append({
            "timestamp": None, "regra_id": "D003", "regra_nome": "IP em Blacklist",
            "severidade": "ALTA", "ip": ip, "fonte": None,
            "descricao": "IP presente na lista de Threat Intelligence",
            "linha_original": None, "origem": "detector",
        })
    for ip, d in (janela or {}).items():
        alertas.append({
            "timestamp": d["fim"], "regra_id": "D004", "regra_nome": "Brute Force (janela temporal)",
            "severidade": "CRITICA" if d["pico"] >= 10 else "ALTA", "ip": ip, "fonte": "auth",
            "descricao": f"{d['pico']} falhas em {d['janela_s']}s ({d['inicio']} → {d['fim']})",
            "linha_original": None, "origem": "detector",
        })
    return alertas
