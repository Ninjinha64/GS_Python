"""
Repositório de USUÁRIOS da plataforma no MySQL (Módulo B — Aula 3).

Por que MySQL aqui? Usuários e permissões exigem integridade relacional
(email único, nível de acesso restrito) — encaixa no modelo relacional.

Segurança:
- TODAS as queries são parametrizadas (placeholders); nenhum dado do usuário
  é concatenado no SQL → SQL Injection neutralizado (cenário B4);
- senhas armazenadas apenas como hash (PBKDF2-SHA256 com salt, via werkzeug);
- autenticação com custo constante para usuário inexistente (anti-enumeração);
- email duplicado vira `EmailDuplicadoError` (cenário B3), não um crash.

Fallback sem Docker: se o MySQL não responder, usa SQLite com o MESMO SQL
(só o estilo do placeholder muda: %s no MySQL, ? no SQLite).
"""
import logging
import os
import re
import sqlite3
from typing import Any, Callable, Optional

from werkzeug.security import check_password_hash, generate_password_hash

import settings

logger = logging.getLogger("securapy.mysql")

REGEX_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")
METODO_HASH: str = "pbkdf2:sha256:600000"
# hash "fantasma" para gastar o mesmo tempo quando o usuário não existe
_HASH_FANTASMA: str = generate_password_hash("senha-inexistente", method=METODO_HASH)


class EmailDuplicadoError(Exception):
    """Já existe usuário com este email."""


class DadosInvalidosError(ValueError):
    """Entrada não passou na validação."""


class BancoIndisponivelError(Exception):
    """Falha de conexão com o banco relacional."""


SQL_CRIAR_TABELA: str = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY {autoinc},
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    nivel_acesso INTEGER NOT NULL CHECK (nivel_acesso BETWEEN 1 AND 5),
    ativo BOOLEAN NOT NULL DEFAULT 1,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def validar_senha(senha: Any) -> None:
    if not isinstance(senha, str) or len(senha) < 8:
        raise DadosInvalidosError("senha deve ter pelo menos 8 caracteres")


def validar_nivel(nivel_acesso: Any) -> None:
    if isinstance(nivel_acesso, bool) or not isinstance(nivel_acesso, int) or not 1 <= nivel_acesso <= 5:
        raise DadosInvalidosError("nivel_acesso deve ser inteiro entre 1 e 5")


def validar_usuario(nome: Any, email: Any, senha: Any, nivel_acesso: Any) -> None:
    """Valida os campos; lança DadosInvalidosError com mensagem amigável."""
    if not isinstance(nome, str) or not 2 <= len(nome.strip()) <= 100:
        raise DadosInvalidosError("nome deve ter entre 2 e 100 caracteres")
    if not isinstance(email, str) or not REGEX_EMAIL.match(email.strip()):
        raise DadosInvalidosError("email inválido")
    validar_senha(senha)
    validar_nivel(nivel_acesso)


class UsuarioRepo:
    """CRUD de usuários + autenticação de operadores."""

    def __init__(
        self,
        conectar: Callable[[], Any],
        placeholder: str,
        modo: str,
        erros_integridade: tuple[type[BaseException], ...],
        erros_banco: tuple[type[BaseException], ...],
    ) -> None:
        self._conectar = conectar          # função que devolve uma conexão DB-API
        self.ph = placeholder              # "%s" (MySQL) ou "?" (SQLite)
        self.modo = modo
        self._erros_integridade = erros_integridade
        self._erros_banco = erros_banco
        self.criar_tabela()

    # --------------------------------------------------------------- infra
    def _sql(self, consulta: str) -> str:
        """Troca o marcador neutro {p} pelo placeholder do driver.
        Só afeta texto FIXO do código — dados vão sempre como parâmetros."""
        return consulta.replace("{p}", self.ph)

    def _executar(self, consulta: str, params: tuple[Any, ...] = (), buscar: Optional[str] = None) -> Any:
        conexao = None
        try:
            conexao = self._conectar()
            cursor = conexao.cursor()
            cursor.execute(self._sql(consulta), params)
            if buscar == "um":
                linha = cursor.fetchone()
                resultado: Any = self._linha_dict(cursor, linha) if linha else None
            elif buscar == "todos":
                resultado = [self._linha_dict(cursor, l) for l in cursor.fetchall()]
            else:
                conexao.commit()
                resultado = cursor.lastrowid if cursor.lastrowid else cursor.rowcount
            cursor.close()
            return resultado
        except self._erros_integridade as e:
            raise EmailDuplicadoError("email já cadastrado") from e
        except self._erros_banco as e:
            logger.error("Erro de banco: %s", type(e).__name__)
            raise BancoIndisponivelError("falha ao acessar o banco de usuários") from e
        finally:
            if conexao is not None:
                conexao.close()

    @staticmethod
    def _linha_dict(cursor: Any, linha: tuple[Any, ...]) -> dict[str, Any]:
        colunas = [c[0] for c in cursor.description]
        return dict(zip(colunas, linha))

    def criar_tabela(self) -> None:
        autoinc = "AUTO_INCREMENT" if self.modo == "mysql" else "AUTOINCREMENT"
        self._executar(SQL_CRIAR_TABELA.format(autoinc=autoinc))

    # ---------------------------------------------------------------- CRUD
    def criar_usuario(self, nome: str, email: str, senha: str, nivel_acesso: int = 1) -> int:
        """Cria usuário. Retorna o id. Lança EmailDuplicadoError / DadosInvalidosError."""
        validar_usuario(nome, email, senha, nivel_acesso)
        return int(self._executar(
            "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES ({p}, {p}, {p}, {p})",
            (nome.strip(), email.strip().lower(), generate_password_hash(senha, method=METODO_HASH), nivel_acesso),
        ))

    def buscar_por_email(self, email: str) -> Optional[dict[str, Any]]:
        return self._executar(
            "SELECT id, nome, email, senha_hash, nivel_acesso, ativo FROM usuarios WHERE email = {p}",
            (str(email).strip().lower(),), buscar="um",
        )

    def buscar_por_id(self, usuario_id: int) -> Optional[dict[str, Any]]:
        return self._executar(
            "SELECT id, nome, email, nivel_acesso, ativo FROM usuarios WHERE id = {p}",
            (int(usuario_id),), buscar="um",
        )

    def listar_usuarios(self) -> list[dict[str, Any]]:
        return self._executar(
            "SELECT id, nome, email, nivel_acesso, ativo FROM usuarios ORDER BY id", buscar="todos",
        )

    def atualizar_nivel(self, usuario_id: int, nivel_acesso: int) -> int:
        validar_nivel(nivel_acesso)
        return int(self._executar(
            "UPDATE usuarios SET nivel_acesso = {p} WHERE id = {p}", (nivel_acesso, int(usuario_id)),
        ))

    def alterar_senha(self, usuario_id: int, nova_senha: str) -> int:
        validar_senha(nova_senha)
        return int(self._executar(
            "UPDATE usuarios SET senha_hash = {p} WHERE id = {p}",
            (generate_password_hash(nova_senha, method=METODO_HASH), int(usuario_id)),
        ))

    def remover_usuario(self, usuario_id: int) -> int:
        return int(self._executar("DELETE FROM usuarios WHERE id = {p}", (int(usuario_id),)))

    # --------------------------------------------------------- autenticação
    def autenticar(self, email: Any, senha: Any) -> Optional[dict[str, Any]]:
        """
        Retorna o usuário (sem o hash) se email+senha conferem; senão None.
        Usuário inexistente e senha errada têm o MESMO resultado e custo.
        """
        if not isinstance(email, str) or not isinstance(senha, str):
            return None
        usuario = self.buscar_por_email(email)
        hash_alvo = usuario["senha_hash"] if usuario else _HASH_FANTASMA
        senha_ok = check_password_hash(hash_alvo, senha)
        if not usuario or not senha_ok or not usuario.get("ativo"):
            return None
        return {k: v for k, v in usuario.items() if k != "senha_hash"}

    def garantir_admin(self, email: str, senha: str) -> bool:
        """Cria o admin inicial (nível 5) se não existir. Usado no boot."""
        if not senha or self.buscar_por_email(email):
            return False
        try:
            self.criar_usuario("Administrador", email, senha, 5)
            logger.info("Usuário administrador inicial criado")
            return True
        except EmailDuplicadoError:
            return False


# ------------------------------------------------------------------ fábricas
def _repo_mysql() -> UsuarioRepo:
    import mysql.connector
    from mysql.connector import errors as myerr

    parametros: dict[str, Any] = dict(
        host=settings.MYSQL_HOST, port=settings.MYSQL_PORT, user=settings.MYSQL_USER,
        password=settings.MYSQL_PASSWORD, database=settings.MYSQL_DATABASE,
        connection_timeout=3,
    )
    mysql.connector.connect(**parametros).close()  # testa a conexão
    return UsuarioRepo(
        conectar=lambda: mysql.connector.connect(**parametros),
        placeholder="%s", modo="mysql",
        erros_integridade=(myerr.IntegrityError,),
        erros_banco=(myerr.Error,),
    )


def repo_sqlite(caminho: Optional[str] = None) -> UsuarioRepo:
    """Repositório SQLite (fallback local e testes). ':memory:' não persiste entre conexões,
    por isso usamos arquivo."""
    caminho = caminho or settings.SQLITE_FALLBACK
    pasta = os.path.dirname(caminho)
    if pasta:
        os.makedirs(pasta, exist_ok=True)
    return UsuarioRepo(
        conectar=lambda: sqlite3.connect(caminho),
        placeholder="?", modo="sqlite",
        erros_integridade=(sqlite3.IntegrityError,),
        erros_banco=(sqlite3.Error,),
    )


def criar_repo() -> UsuarioRepo:
    """Conecta ao MySQL; se indisponível e o fallback estiver ativo, usa SQLite."""
    try:
        repo = _repo_mysql()
        logger.info("Conectado ao MySQL")
        return repo
    except Exception as e:  # driver ausente, conexão recusada, credencial errada...
        if not settings.PERMITIR_FALLBACK:
            raise BancoIndisponivelError("MySQL indisponível") from e
        logger.warning("MySQL indisponível (%s). Usando SQLite local.", type(e).__name__)
        return repo_sqlite()
