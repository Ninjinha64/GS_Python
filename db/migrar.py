"""
Migração / ingestão inicial (Módulo B, requisito 3).

Lê os logs via núcleo do 1º semestre, roda o pipeline completo e popula o
MongoDB; opcionalmente cria o usuário administrador no MySQL.

Uso:
    python -m db.migrar                 # ingere logs/ no MongoDB
    python -m db.migrar --limpar        # apaga as coleções antes
    python -m db.migrar --criar-admin   # cria admin (pede a senha)
    python -m db.migrar --relatorio     # exporta saida/relatorio_*.json

Obs.: sem MongoDB real (modo mongomock) os dados vivem só na memória deste
processo — nesse caso a própria API faz a ingestão ao subir.
"""
import argparse
import getpass
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import servicos  # noqa: E402
import settings  # noqa: E402
from db import mongo_repo, mysql_repo  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description="Ingestão inicial do SecuraPy Platform")
    parser.add_argument("--limpar", action="store_true", help="apaga eventos/alertas antes")
    parser.add_argument("--criar-admin", action="store_true", help="cria o usuário administrador")
    parser.add_argument("--relatorio", action="store_true", help="exporta relatório JSON ao final")
    args = parser.parse_args(argv)

    repo = mongo_repo.criar_repo()
    print(f"[MongoDB] modo: {repo.modo}")
    if args.limpar:
        repo.limpar()
        print("[MongoDB] coleções limpas")

    resumo = servicos.analisar_logs_padrao(repo, notificar=False)
    print(f"[OK] {resumo['eventos_processados']} eventos lidos {resumo['eventos_por_fonte']} "
          f"| novos no banco: {resumo['eventos_novos']}")
    print(f"[OK] {resumo['alertas_gerados']} alertas (regras: {resumo['alertas_regras']}, "
          f"detector: {resumo['alertas_detector']}) | ML: {resumo['ml_status']}")
    print("[OK] Top 5 IPs por eventos:")
    for item in repo.top_ips(5):
        print(f"      {item['ip']:<16} {item['total']}")

    if args.criar_admin:
        usuarios = mysql_repo.criar_repo()
        print(f"[Usuários] modo: {usuarios.modo}")
        email = input(f"Email do admin [{settings.ADMIN_EMAIL}]: ").strip() or settings.ADMIN_EMAIL
        senha = settings.ADMIN_SENHA or getpass.getpass("Senha (mín. 8): ")
        try:
            usuarios.criar_usuario("Administrador", email, senha, 5)
            print("[OK] admin criado")
        except mysql_repo.EmailDuplicadoError:
            print("[!] já existe usuário com esse email")
        except mysql_repo.DadosInvalidosError as e:
            print(f"[!] {e}")

    if args.relatorio:
        print(f"[OK] relatório: {servicos.exportar_relatorio(repo)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    main()
