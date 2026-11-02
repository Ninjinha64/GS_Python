"""
Coletor de logs — reaproveitado do 1º semestre (CP1).

Evoluções para a GS:
- Além do campo texto `detalhes` (mantido por compatibilidade com o motor de
  regras e o detector da CP1), cada evento agora traz campos estruturados
  (`usuario`, `porta`, `url`, `status`...) que alimentam o banco e o ML.
- `print` foi trocado por `logging`, para os avisos aparecerem no log da API.
- `carregar_log` aceita também linhas em memória (usado pelo POST /api/analisar).

Contrato do EVENTO (dict) — "cola" entre os módulos:
    {
        "timestamp": "2025-02-20 08:15:01",   # str ordenável
        "fonte": "auth" | "firewall" | "web",
        "tipo": "FAIL" | "OK" | "BLOCK" | "ALLOW" | "GET" | "POST" | ...,
        "ip": "185.220.101.1",
        "detalhes": "usuario=admin",          # texto (compatível com a CP1)
        "linha_original": "...",
        ... campos específicos por fonte ...
    }
"""
import logging
import os

logger = logging.getLogger("securapy.coletor")

FONTES_VALIDAS = ("auth", "firewall", "web")


def _extrair_chave_valor(partes):
    """Converte ['usuario=admin', 'ip=1.2.3.4'] em {'usuario': 'admin', 'ip': '1.2.3.4'}."""
    campos = {}
    for parte in partes:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            campos[chave] = valor
    return campos


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 5:
        raise ValueError("Linha mal formatada (menos de 5 partes)")

    campos = _extrair_chave_valor(partes[3:])
    usuario = campos.get("usuario", "")
    ip = campos.get("ip", "")
    if not ip:
        raise ValueError("Linha sem IP")

    return {
        "timestamp": f"{partes[0]} {partes[1]}",
        "fonte": "auth",
        "tipo": partes[2],
        "ip": ip,
        "usuario": usuario,
        "detalhes": f"usuario={usuario}",
        "linha_original": linha.strip(),
    }


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 7:
        raise ValueError("Linha mal formatada (menos de 7 partes)")

    campos = _extrair_chave_valor(partes[3:])
    ip_src = campos.get("src", "")
    if not ip_src:
        raise ValueError("Linha sem IP de origem")
    dport = campos.get("dport", "")

    return {
        "timestamp": f"{partes[0]} {partes[1]}",
        "fonte": "firewall",
        "tipo": partes[2],
        "ip": ip_src,
        "proto": campos.get("proto", ""),
        "ip_destino": campos.get("dst", ""),
        "porta": int(dport) if dport.isdigit() else None,
        "detalhes": f"proto={campos.get('proto', '')} dst={campos.get('dst', '')} dport={dport}",
        "linha_original": linha.strip(),
    }


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 6:
        raise ValueError("Linha mal formatada (menos de 6 partes)")

    campos = _extrair_chave_valor(partes[3:])
    ip = campos.get("ip", "")
    if not ip:
        raise ValueError("Linha sem IP")
    status = campos.get("status", "")
    url = campos.get("url", "")

    return {
        "timestamp": f"{partes[0]} {partes[1]}",
        "fonte": "web",
        "tipo": partes[2],
        "ip": ip,
        "url": url,
        "status": int(status) if status.isdigit() else None,
        "detalhes": f"url={url} status={status}",
        "linha_original": linha.strip(),
    }


# Despacho por fonte (dict de funções em vez de if/elif encadeado)
PARSERS = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}


def parsear_linhas(linhas, fonte, origem="<memoria>"):
    """
    Parseia um iterável de linhas de uma fonte. Linhas malformadas são
    registradas e ignoradas (não travam a ingestão).
    Retorna (eventos, quantidade_de_linhas_ignoradas).
    """
    parser = PARSERS.get(fonte)
    if parser is None:
        raise ValueError(f"Fonte desconhecida: {fonte}")

    eventos = []
    ignoradas = 0
    for num_linha, linha in enumerate(linhas, 1):
        linha = linha.strip()
        if not linha:
            continue
        try:
            eventos.append(parser(linha))
        except ValueError as e:
            ignoradas += 1
            logger.warning("Linha %d ignorada em %s: %s", num_linha, origem, e)
    return eventos, ignoradas


def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
    - caminho_arquivo: str com o path do arquivo
    - fonte: str indicando o tipo ("auth", "firewall", "web")
    - Retorna: list[dict] com os eventos parseados (lista vazia em caso de erro)
    """
    try:
        if os.path.getsize(caminho_arquivo) == 0:
            logger.warning("Arquivo vazio: %s", caminho_arquivo)
            return []
        with open(caminho_arquivo, "r", encoding="utf-8", errors="replace") as f:
            eventos, _ = parsear_linhas(f, fonte, origem=caminho_arquivo)
            return eventos
    except FileNotFoundError:
        logger.error("Arquivo não encontrado: %s", caminho_arquivo)
    except (OSError, ValueError) as e:
        logger.error("Erro ao ler %s: %s", caminho_arquivo, e)
    return []


def identificar_fonte(nome_arquivo):
    """Deduz a fonte pelo nome do arquivo (auth/firewall/web) ou None."""
    nome = nome_arquivo.lower()
    for fonte in FONTES_VALIDAS:
        if fonte in nome:
            return fonte
    return None


def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log da pasta e retorna lista unificada.
    Usa os.listdir() para encontrar os arquivos.
    """
    todos_eventos = []
    if not os.path.isdir(pasta_logs):
        logger.error("A pasta %s não existe.", pasta_logs)
        return todos_eventos

    for arquivo in sorted(os.listdir(pasta_logs)):
        caminho_completo = os.path.join(pasta_logs, arquivo)
        if not os.path.isfile(caminho_completo):
            continue
        fonte = identificar_fonte(arquivo)
        if fonte:
            todos_eventos.extend(carregar_log(caminho_completo, fonte))
        else:
            logger.info("Ignorando arquivo desconhecido: %s", arquivo)
    return todos_eventos
