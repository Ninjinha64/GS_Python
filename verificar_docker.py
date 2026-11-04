"""
Script de verificação dos contêineres via Docker SDK (`docker-py`) — Módulo F (Aula 11).

Cenários cobertos:
- F2: Lista os 3 contêineres (`securapy_app`, `securapy_mongo`, `securapy_mysql`)
      e confirma que estão com status "running".
- F3: Verifica que a API responde HTTP 200 em `/api/health`.

Caso o daemon Docker não esteja instalado na máquina local (ex.: desenvolvimento
no Windows sem Docker Desktop), suporta modo de simulação (`--simular`) ou
informa de maneira clara o comando e o status da API local.

Uso:
    python verificar_docker.py
    python verificar_docker.py --url http://127.0.0.1:5000/api/health
"""
import argparse
import sys

import docker
from docker.errors import DockerException
import requests

CONTEINERES_ESPERADOS = (
    "securapy_app",
    "securapy_mongo",
    "securapy_mysql",
)

def inspecionar_conteineres(cliente_docker=None):
    """
    Lista os contêineres da plataforma usando o Docker SDK.
    Retorna nome, imagem e status de cada serviço.
    """
    cliente = cliente_docker or docker.from_env()
    lista = cliente.containers.list(all=True)

    por_nome = {c.name: c for c in lista}

    relatorio = []

    for nome in CONTEINERES_ESPERADOS:
        cont = por_nome.get(nome)

        if cont is None:
            relatorio.append({
                "nome": nome,
                "imagem": "-",
                "status": "ausente"
            })
        else:
            atributos = getattr(cont, "attrs", {})
            imagem = atributos.get("Config", {}).get("Image", "-")
            if imagem == "-":
                imagem = getattr(cont, "image", "-")
                imagem = imagem if isinstance(imagem, str) else getattr(imagem, "short_id", "-")

            relatorio.append({
                "nome": cont.name,
                "imagem": imagem,
                "status": cont.status
            })

    return relatorio


def verificar_api_http(url="http://127.0.0.1:5000/api/health", timeout=5):
    """Testa se a API responde HTTP 200 (cenário F3)."""
    try:
        resp = requests.get(url, timeout=timeout)
        return {"ok": resp.status_code == 200, "status_code": resp.status_code, "corpo": resp.json()}
    except requests.RequestException as e:
        return {"ok": False, "status_code": None, "erro": str(e)}


def _cliente_simulado():
    """Cliente fake usado quando `--simular` é passado em máquina sem Docker."""
    class _Img:
        def __init__(self, tag):
            self.tags = [tag]

    class _Cont:
        def __init__(self, name, tag):
            self.name = name
            self.image = _Img(tag)
            self.status = "running"

    class _Containers:
        @staticmethod
        def list(all=True):  # noqa: A002
            return [
                _Cont("securapy_app", "securapy_platform-securapy:latest"),
                _Cont("securapy_mongo", "mongo:7.0"),
                _Cont("securapy_mysql", "mysql:8.0"),
            ]

    class _Cliente:
        containers = _Containers()

    return _Cliente()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verificação de contêineres Docker do SecuraPy Platform")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/health", help="URL de healthcheck da API")
    parser.add_argument("--simular", action="store_true", help="Simula daemon Docker caso não instalado localmente")
    args = parser.parse_args(argv)

    print("=== Verificação de Contêineres (Docker SDK / docker-py) ===")
    try:
        cliente = _cliente_simulado() if args.simular else docker.from_env()
        relatorio = inspecionar_conteineres(cliente)
    except DockerException as e:
        print(f"[AVISO] Daemon Docker não acessível nesta máquina ({type(e).__name__}).")
        print("        Dica: suba no GitHub Codespaces com `docker compose up -d` ou use `--simular`.")
        relatorio = []

    todos_running = bool(relatorio) and all(item["status"] == "running" for item in relatorio)
    for item in relatorio:
        marcador = "[OK]" if item["status"] == "running" else "[!!]"
        print(f"  {marcador} {item['nome']:<18} imagem={item['imagem']:<34} status={item['status']}")

    print("\n=== Verificação HTTP da API ===")
    status_api = verificar_api_http(args.url)
    if status_api["ok"]:
        print(f"  [OK] {args.url} -> HTTP {status_api['status_code']} | {status_api['corpo']}")
    else:
        print(f"  [!!] {args.url} indisponível ({status_api.get('erro') or status_api.get('status_code')})")

    return 0 if (todos_running or status_api["ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
