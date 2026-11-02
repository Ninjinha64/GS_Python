"""
Publicador de alertas: ponte entre o pipeline de análise e o servidor TCP.

- Se o servidor está EMBUTIDO no mesmo processo (API), chama o broadcast direto.
- Senão, envia pela porta de ingestão (servidor rodando em outro terminal).
Falhas de rede são registradas e nunca derrubam a análise.
"""
import json
import logging
import os
import socket

import settings
from alertas import servidor_alertas

logger = logging.getLogger("securapy.publicador")

SEVERIDADES_NOTIFICADAS = frozenset(
    s.strip().upper() for s in os.getenv("SECURAPY_ALERTAS_SEVERIDADES", "CRITICA,ALTA").split(","))


def _enviar_remoto(alerta):
    msg = json.dumps({"token": os.getenv("SECURAPY_ALERTAS_TOKEN", ""), "alerta": alerta},
                     ensure_ascii=False, default=str)
    with socket.create_connection(("127.0.0.1", settings.ALERTAS_PORTA_INGESTAO), timeout=1) as s:
        s.sendall(msg.encode("utf-8"))
        s.recv(16)


def publicar(alertas):
    """Publica os alertas de severidade relevante. Retorna quantos foram enviados."""
    relevantes = [a for a in alertas if str(a.get("severidade", "")).upper() in SEVERIDADES_NOTIFICADAS]
    if not relevantes:
        return 0
    embutido = servidor_alertas.servidor_embutido()
    enviados = 0
    for alerta in relevantes:
        limpo = {k: v for k, v in alerta.items() if k not in ("_id", "hash")}
        try:
            if embutido:
                embutido.broadcast_alerta(limpo)
            else:
                _enviar_remoto(limpo)
            enviados += 1
        except OSError as e:
            logger.info("Servidor de alertas indisponível (%s) — publicação ignorada", type(e).__name__)
            break
    return enviados
