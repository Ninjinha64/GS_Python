"""
Extração de features por IP (Módulo C).

Transforma a lista de EVENTOS (contrato do coletor) em um vetor numérico por
IP — a mesma função é usada no treino e na classificação, garantindo que o
modelo sempre veja as features na mesma ordem.
"""
from core.regras import aplicar_regras

# Ordem FIXA das colunas (tupla = imutável). O modelo salvo guarda esta lista.
FEATURES = (
    "fails_auth",        # nº de FAILs no auth.log
    "logins_ok",         # nº de logins OK
    "portas_distintas",  # nº de portas distintas bloqueadas (port scan)
    "bloqueios_fw",      # nº total de BLOCKs no firewall
    "web_erros",         # nº de requisições web com status >= 400
    "web_total",         # nº total de requisições web
    "alertas_regra",     # nº de alertas do motor de regras para o IP
    "em_blacklist",      # 1 se o IP está na blacklist de Threat Intel
)


def extrair_features(eventos, blacklist=frozenset(), regras=None):
    """
    Retorna dict {ip: {feature: valor}} para todos os IPs dos eventos.
    `regras` (opcional) permite contar alertas do motor de regras por IP.
    """
    por_ip = {}
    portas = {}  # ip -> set de portas bloqueadas

    def base(ip):
        return por_ip.setdefault(ip, {nome: 0 for nome in FEATURES})

    for ev in eventos:
        ip = ev.get("ip")
        if not ip:
            continue
        f = base(ip)
        fonte, tipo = ev.get("fonte"), ev.get("tipo")
        if fonte == "auth":
            if tipo == "FAIL":
                f["fails_auth"] += 1
            elif tipo == "OK":
                f["logins_ok"] += 1
        elif fonte == "firewall" and tipo == "BLOCK":
            f["bloqueios_fw"] += 1
            if ev.get("porta") is not None:
                portas.setdefault(ip, set()).add(ev["porta"])
        elif fonte == "web":
            f["web_total"] += 1
            status = ev.get("status")
            if isinstance(status, int) and status >= 400:
                f["web_erros"] += 1

    for ip, conjunto in portas.items():
        por_ip[ip]["portas_distintas"] = len(conjunto)

    if regras:
        for alerta in aplicar_regras(eventos, regras):
            if alerta.get("ip") in por_ip:
                por_ip[alerta["ip"]]["alertas_regra"] += 1

    for ip in por_ip:
        por_ip[ip]["em_blacklist"] = 1 if ip in blacklist else 0
    return por_ip


def vetor(features_ip, ordem=FEATURES):
    """dict de features → lista na ordem esperada pelo modelo."""
    return [float(features_ip.get(nome, 0)) for nome in ordem]
