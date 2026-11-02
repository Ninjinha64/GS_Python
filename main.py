"""
Ponto de entrada unificado do SecuraPy Platform (`main.py`).

Modos de execução:
  python main.py                  # Sobe a API Flask + Dashboard + Servidor TCP de alertas
  python main.py --analisar       # Executa o pipeline ponta a ponta (CLI), persiste e exporta JSON
  python main.py --treinar        # Treina e persiste o modelo de Machine Learning
  python main.py --servidor-tcp   # Sobe apenas o servidor TCP de alertas em primeiro plano
"""
import argparse
import logging
import os

from alertas import servidor_alertas
from api.app import criar_app
from db import mongo_repo, mysql_repo
from ml import treinar
import servicos
import settings


def executar_pipeline_cli():
    """Demonstrador ponta a ponta em modo CLI (item 4 do enunciado)."""
    print("=" * 64)
    print(" SecuraPy Platform — Pipeline Ponta a Ponta")
    print("=" * 64)

    repo = mongo_repo.criar_repo()
    usuarios = mysql_repo.criar_repo()
    usuarios.garantir_admin(settings.ADMIN_EMAIL, settings.ADMIN_SENHA or "CyberShield@2026")
    print(f"[1/4] Bancos prontos (Mongo={repo.modo}, Usuários={usuarios.modo})")

    resumo = servicos.analisar_logs_padrao(repo, notificar=True)
    print(f"[2/4] Logs ingeridos: {resumo['eventos_processados']} eventos {resumo['eventos_por_fonte']}")
    print(f"[3/4] Alertas gerados: {resumo['alertas_gerados']} (regras={resumo['alertas_regras']}, "
          f"detector={resumo['alertas_detector']}) | ML={resumo['ml_status']}")

    print("\nTop IPs por score de risco (ML + Detector):")
    for item in resumo["top_ips_risco"][:5]:
        print(f"  - {item['ip']:<15} score_ml={item['score_ml']:.2f} "
              f"rotulo={item['rotulo_ml']:<6} anomalo={item['anomalo']} | {item['motivos']}")

    caminho = servicos.exportar_relatorio(repo)
    print(f"\n[4/4] Relatório JSON exportado em: {caminho}")
    return resumo


def main():
    parser = argparse.ArgumentParser(description="SecuraPy Platform — SIEM")
    parser.add_argument("--analisar", action="store_true", help="Roda análise ponta a ponta e exporta JSON")
    parser.add_argument("--treinar", action="store_true", help="Treina o modelo de Machine Learning")
    parser.add_argument("--servidor-tcp", action="store_true", help="Inicia apenas o servidor TCP de alertas")
    parser.add_argument("--porta", type=int, default=int(os.getenv("PORT", "5000")), help="Porta HTTP da API/Web")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if args.treinar:
        treinar.treinar()
        return

    if args.analisar:
        executar_pipeline_cli()
        return

    if args.servidor_tcp:
        servidor_alertas.iniciar_servidor()
        return

    app = criar_app(popular_inicial=True, iniciar_socket=True)
    print("=" * 64)
    print(" SecuraPy Platform no ar!")
    print(f" Dashboard Web : http://127.0.0.1:{args.porta}/")
    print(f" API REST      : http://127.0.0.1:{args.porta}/api/health")
    print(f" Alertas TCP   : 127.0.0.1:{settings.ALERTAS_PORTA} (use `python -m alertas.cliente_alertas`)")
    print(f" Login padrão  : {settings.ADMIN_EMAIL} / CyberShield@2026")
    print("=" * 64)
    app.run(host="0.0.0.0", port=args.porta, debug=False)


if __name__ == "__main__":
    main()
