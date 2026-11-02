"""
Integridade do modelo (reaproveita `hashlib` do 1º semestre).

Um `.pkl` é código executável na prática (pickle). Antes de carregar,
conferimos o SHA-256 contra o valor registrado no treino: se alguém trocar
o arquivo, o carregamento é recusado.
"""
import hashlib
import hmac
import os


class ModeloAdulteradoError(Exception):
    """O hash do arquivo do modelo não confere com o registrado."""


def calcular_sha256(caminho, bloco=65536):
    """SHA-256 do arquivo lendo em blocos (não carrega tudo na memória)."""
    sha = hashlib.sha256()
    with open(caminho, "rb") as f:
        for pedaco in iter(lambda: f.read(bloco), b""):
            sha.update(pedaco)
    return sha.hexdigest()


def registrar_hash(caminho_modelo, caminho_hash):
    """Calcula e grava o hash no formato do `sha256sum` ("<hash>  <arquivo>")."""
    digest = calcular_sha256(caminho_modelo)
    with open(caminho_hash, "w", encoding="utf-8") as f:
        f.write(f"{digest}  {os.path.basename(caminho_modelo)}\n")
    return digest


def ler_hash_registrado(caminho_hash):
    with open(caminho_hash, encoding="utf-8") as f:
        return f.read().split()[0].strip().lower()


def verificar_integridade(caminho_modelo, caminho_hash):
    """
    Retorna o hash se confere; lança ModeloAdulteradoError se não confere
    ou se o arquivo de hash não existe.
    """
    try:
        esperado = ler_hash_registrado(caminho_hash)
    except (OSError, IndexError) as e:
        raise ModeloAdulteradoError("hash de referência ausente ou ilegível") from e
    atual = calcular_sha256(caminho_modelo)
    # compare_digest: comparação em tempo constante
    if not hmac.compare_digest(atual, esperado):
        raise ModeloAdulteradoError(f"hash não confere (esperado {esperado[:12]}…, atual {atual[:12]}…)")
    return atual
