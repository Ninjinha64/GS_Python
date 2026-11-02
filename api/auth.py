"""
Autenticação e autorização da API (Módulo D + Bônus JWT).

Suporta dois tipos de token no header `Authorization: Bearer <token>`:
1. **JWT (Bônus +0,20)**: gerado em `POST /api/login` com expiração, `sub` (email)
   e `nivel` (1 a 5), assinado com HS256 usando `settings.SECRET_KEY`.
2. **Token estático de API** (opcional via `SECURAPY_API_TOKEN`): útil para scripts
   de automação ou testes simples sem precisar de login prévio.

Sem token válido nas rotas protegidas → HTTP 401.
"""
from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import os

from flask import g, jsonify, request, session
import jwt

import settings

ALGORITMO_JWT = "HS256"


def gerar_token_jwt(usuario):
    """
    Recebe dict do usuário (`id`, `email`, `nome`, `nivel_acesso`) e
    retorna string JWT assinada com expiração configurável.
    """
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario.get("email")),
        "uid": usuario.get("id"),
        "nome": usuario.get("nome"),
        "nivel": int(usuario.get("nivel_acesso", 1)),
        "iat": agora,
        "exp": agora + timedelta(minutes=settings.JWT_EXPIRACAO_MIN),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITMO_JWT)


def verificar_token(token):
    """
    Valida um token Bearer (JWT ou token estático configurado em env).
    Retorna dict com dados do operador ou None se inválido/expirado.
    """
    if not token or not isinstance(token, str):
        return None

    token_estatico = os.getenv("SECURAPY_API_TOKEN", "")
    if token_estatico and hmac.compare_digest(token, token_estatico):
        return {"sub": "automacao@cybershield.local", "nome": "Automação API", "nivel": 5}

    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITMO_JWT])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def extrair_bearer():
    """Extrai o token do cabeçalho `Authorization: Bearer <token>`."""
    cabecalho = request.headers.get("Authorization", "")
    partes = cabecalho.split(None, 1)
    if len(partes) == 2 and partes[0].lower() == "bearer":
        return partes[1].strip()
    return None


def exigir_token(nivel_minimo=1):
    """
    Decorator para rotas da API que exigem `Authorization: Bearer <token>`.
    Retorna 401 se ausente/inválido e 403 se o nível de acesso for insuficiente.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = extrair_bearer()
            dados = verificar_token(token)
            if not dados:
                return jsonify({"erro": "Não autorizado. Informe um token Bearer válido."}), 401
            if int(dados.get("nivel", 1)) < nivel_minimo:
                return jsonify({"erro": "Permissão insuficiente para esta operação."}), 403
            g.operador = dados
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def operador_logado_web():
    """Retorna o operador autenticado na sessão web (dashboard) ou via Bearer."""
    if session.get("operador"):
        return session["operador"]
    dados = verificar_token(extrair_bearer())
    return dados
