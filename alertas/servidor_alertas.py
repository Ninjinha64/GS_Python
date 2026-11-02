"""
Servidor TCP de alertas em tempo real — reaproveitado do 1º semestre.

Evoluções para a GS:
- encapsulado em uma classe (estado sem variáveis globais soltas);
- pode rodar SOZINHO (`python -m alertas.servidor_alertas`) ou EMBUTIDO na
  API (thread em background) — a API chama `broadcast_alerta` diretamente;
- porta de INGESTÃO (só localhost por padrão, com token opcional) para que
  outros processos publiquem alertas (ver `alertas/publicador.py`);
- `/historico` agora funciona (deque com os últimos 50 alertas);
- corrigido o bug da CP1: `formatar_alerta` lia `regra`, mas o campo é `regra_nome`.

Protocolo console: texto UTF-8, uma mensagem por linha.
Comandos: /status  /historico  /ajuda  /sair
"""
import hmac
import json
import logging
import os
import socket
import sys
import threading
from collections import deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import settings  # noqa: E402

logger = logging.getLogger("securapy.alertas")

CORES = {"CRITICA": "\033[91m", "ALTA": "\033[93m", "MEDIA": "\033[96m"}
RESET = "\033[0m"
MAX_LINHA = 8192


def formatar_hora():
    return datetime.now().strftime("%H:%M:%S")


def formatar_alerta(alerta, cor=True):
    """Converte dict de alerta em string formatada para exibição."""
    ts = alerta.get("timestamp") or formatar_hora()
    ts = ts.split()[-1] if isinstance(ts, str) else ts
    sev = alerta.get("severidade", "INFO")
    regra = alerta.get("regra_nome") or alerta.get("regra") or "Desconhecida"
    ip = alerta.get("ip") or "-"
    desc = alerta.get("descricao") or ""
    score = alerta.get("score_risco")
    extra = f" (risco ML {score:.2f})" if isinstance(score, (int, float)) and score else ""
    texto = f"[{ts}] [{sev}] {regra} - {ip} - {desc}{extra}"
    if cor and sev in CORES:
        return f"{CORES[sev]}{texto}{RESET}"
    return texto


class ServidorAlertas:
    def __init__(self, host="0.0.0.0", porta=None, porta_ingestao=None, host_ingestao="127.0.0.1"):
        self.host = host
        self.porta = porta or settings.ALERTAS_PORTA
        self.host_ingestao = host_ingestao
        self.porta_ingestao = porta_ingestao or settings.ALERTAS_PORTA_INGESTAO
        self.clientes = {}                 # socket -> (ip, porta)
        self.historico = deque(maxlen=50)  # últimos alertas (fila circular)
        self.lock = threading.Lock()
        self.rodando = threading.Event()
        self._sockets = []

    # ---------------------------------------------------------------- start
    def iniciar(self, em_background=False):
        """Abre as portas. Em background, retorna logo após subir as threads."""
        console = self._abrir_socket(self.host, self.porta)
        ingestao = self._abrir_socket(self.host_ingestao, self.porta_ingestao)
        self.rodando.set()
        logger.info("Servidor de alertas em %s:%s (ingestão %s:%s)",
                    self.host, self.porta, self.host_ingestao, self.porta_ingestao)
        threading.Thread(target=self._aceitar_ingestao, args=(ingestao,), daemon=True).start()
        if em_background:
            threading.Thread(target=self._aceitar_consoles, args=(console,), daemon=True).start()
        else:
            print("=== Servidor de Alertas SecuraPy ===")
            print(f"Consoles: {self.host}:{self.porta} | Ingestão: {self.host_ingestao}:{self.porta_ingestao}")
            print("Aguardando conexões... (Ctrl+C para sair)\n")
            try:
                self._aceitar_consoles(console)
            except KeyboardInterrupt:
                print("\nEncerrando servidor.")
            finally:
                self.parar()

    def _abrir_socket(self, host, porta):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, porta))
        s.listen()
        self._sockets.append(s)
        return s

    def parar(self):
        self.rodando.clear()
        with self.lock:
            for c in list(self.clientes):
                try:
                    c.close()
                except OSError:
                    pass
            self.clientes.clear()
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass

    # -------------------------------------------------------------- consoles
    def _aceitar_consoles(self, servidor):
        while self.rodando.is_set():
            try:
                conexao, endereco = servidor.accept()
            except OSError:
                break
            with self.lock:
                self.clientes[conexao] = endereco
            logger.info("Console conectado: %s:%s", *endereco)
            print(f"[{formatar_hora()}] Cliente conectado: {endereco[0]}:{endereco[1]}")
            threading.Thread(target=self.tratar_cliente, args=(conexao, endereco), daemon=True).start()

    def _enviar(self, conexao, texto):
        conexao.sendall((texto + "\n").encode("utf-8"))

    def tratar_cliente(self, conexao, endereco):
        """Gerencia comunicação com um console (roda em thread)."""
        try:
            self._enviar(conexao, "Conectado ao SecuraPy Platform.\nComandos: /status, /historico, /ajuda, /sair")
            while self.rodando.is_set():
                dados = conexao.recv(1024)
                if not dados:
                    break
                comando = dados.decode("utf-8", errors="replace").strip()
                if comando == "/sair":
                    break
                if comando == "/status":
                    with self.lock:
                        n = len(self.clientes)
                    self._enviar(conexao, f"Consoles conectados: {n} | Alertas no histórico: {len(self.historico)}")
                elif comando == "/historico":
                    with self.lock:
                        itens = list(self.historico)
                    self._enviar(conexao, "\n".join(formatar_alerta(a) for a in itens) or "Histórico vazio.")
                elif comando == "/ajuda":
                    self._enviar(conexao, "/status — consoles conectados | /historico — últimos 50 alertas | /sair")
                else:
                    self._enviar(conexao, "Comando não reconhecido. Use /ajuda.")
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
            pass
        finally:
            with self.lock:
                self.clientes.pop(conexao, None)
            print(f"[{formatar_hora()}] Cliente desconectado: {endereco[0]}:{endereco[1]}")
            try:
                conexao.close()
            except OSError:
                pass

    def broadcast_alerta(self, alerta):
        """Envia um alerta (dict ou str) para todos os consoles conectados."""
        texto = formatar_alerta(alerta) if isinstance(alerta, dict) else str(alerta)
        with self.lock:
            if isinstance(alerta, dict):
                self.historico.append(alerta)
            mortas = []
            for conexao in self.clientes:
                try:
                    self._enviar(conexao, texto)
                except OSError:
                    mortas.append(conexao)
            for conexao in mortas:
                self.clientes.pop(conexao, None)
            return len(self.clientes)

    # -------------------------------------------------------------- ingestão
    def _aceitar_ingestao(self, servidor):
        """Recebe alertas de outros processos: uma linha JSON {"token":..., "alerta": {...}}."""
        token_esperado = os.getenv("SECURAPY_ALERTAS_TOKEN", "")
        while self.rodando.is_set():
            try:
                conexao, _ = servidor.accept()
            except OSError:
                break
            with conexao:
                try:
                    conexao.settimeout(2)
                    bruto = conexao.recv(MAX_LINHA).decode("utf-8")
                    msg = json.loads(bruto)
                    if token_esperado and not hmac.compare_digest(str(msg.get("token", "")), token_esperado):
                        conexao.sendall(b"ERRO token\n")
                        continue
                    if isinstance(msg.get("alerta"), dict):
                        self.broadcast_alerta(msg["alerta"])
                        conexao.sendall(b"OK\n")
                except (ValueError, OSError, socket.timeout):
                    logger.warning("Mensagem de ingestão inválida descartada")


# Instância usada quando o servidor roda embutido na API
_servidor_embutido = None


def iniciar_embutido():
    """Sobe o servidor em background (chamado pela API). Idempotente."""
    global _servidor_embutido
    if _servidor_embutido is None:
        servidor = ServidorAlertas()
        try:
            servidor.iniciar(em_background=True)
            _servidor_embutido = servidor
        except OSError as e:
            logger.warning("Servidor de alertas embutido não iniciou (%s) — porta em uso?", e)
    return _servidor_embutido


def servidor_embutido():
    return _servidor_embutido


def iniciar_servidor(host="0.0.0.0", porta=None):
    """Compatível com a CP1: inicia o servidor em primeiro plano."""
    ServidorAlertas(host=host, porta=porta).iniciar()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    iniciar_servidor()
