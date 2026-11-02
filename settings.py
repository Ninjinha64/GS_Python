"""
Configuração central do SecuraPy Platform.

Todos os segredos/endereços vêm de VARIÁVEIS DE AMBIENTE (nunca hardcoded).
Veja `.env.example`. Os valores padrão só servem para desenvolvimento local.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _carregar_dotenv(caminho=os.path.join(BASE_DIR, ".env")):
    """Leitor mínimo de .env (sem dependência extra). Não sobrescreve o ambiente."""
    if not os.path.isfile(caminho):
        return
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            chave, valor = linha.split("=", 1)
            os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


_carregar_dotenv()


def _bool(nome, padrao="0"):
    return os.getenv(nome, padrao).strip().lower() in ("1", "true", "sim", "yes")


# --- Caminhos ---------------------------------------------------------------
PASTA_LOGS = os.getenv("SECURAPY_PASTA_LOGS", os.path.join(BASE_DIR, "logs"))
ARQUIVO_REGRAS = os.getenv("SECURAPY_REGRAS", os.path.join(BASE_DIR, "config", "regras.json"))
PASTA_SAIDA = os.path.join(BASE_DIR, "saida")
ARQUIVO_LOG_ACESSO = os.getenv("SECURAPY_LOG_ACESSO", os.path.join(BASE_DIR, "saida", "acesso.log"))

# --- MongoDB (eventos/alertas) ---------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "securapy")
RETENCAO_DIAS = int(os.getenv("SECURAPY_RETENCAO_DIAS", "90"))

# --- MySQL (usuários/permissões) -------------------------------------------
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "securapy")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "securapy")
SQLITE_FALLBACK = os.getenv("SECURAPY_SQLITE", os.path.join(BASE_DIR, "saida", "securapy_local.db"))

# Sem Docker? Se os bancos reais não responderem, usa mongomock + SQLite.
PERMITIR_FALLBACK = _bool("SECURAPY_PERMITIR_FALLBACK", "1")

# --- API / Segurança --------------------------------------------------------
# Em produção SECRET_KEY é obrigatória; em dev gera uma aleatória por execução.
SECRET_KEY = os.getenv("SECURAPY_SECRET_KEY") or os.urandom(32).hex()
JWT_EXPIRACAO_MIN = int(os.getenv("SECURAPY_JWT_EXP_MIN", "60"))
ADMIN_EMAIL = os.getenv("SECURAPY_ADMIN_EMAIL", "admin@cybershield.local")
ADMIN_SENHA = os.getenv("SECURAPY_ADMIN_SENHA", "")  # se vazio, admin não é criado

# --- Alertas em tempo real (socket TCP) ------------------------------------
ALERTAS_HOST = os.getenv("SECURAPY_ALERTAS_HOST", "127.0.0.1")
ALERTAS_PORTA = int(os.getenv("SECURAPY_ALERTAS_PORTA", "9999"))
ALERTAS_PORTA_INGESTAO = int(os.getenv("SECURAPY_ALERTAS_PORTA_INGESTAO", "9998"))

# --- LLM --------------------------------------------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODELO = os.getenv("OPENAI_MODELO", "gpt-4o-mini")

# --- Threat Intelligence ----------------------------------------------------
BLACKLIST = frozenset(
    ip.strip() for ip in os.getenv(
        "SECURAPY_BLACKLIST", "185.220.101.1,45.33.32.156,91.240.118.172,23.94.5.100"
    ).split(",") if ip.strip()
)
