# ==============================================================================
# Dockerfile — SecuraPy Platform (Módulo F — Aula 11)
# Empacota a aplicação Python com usuário não-root, modelo ML pré-treinado e
# portas expostas para API/Dashboard (5000) e Servidor TCP de Alertas (9999).
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Instala dependências primeiro para aproveitar cache de camadas
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código-fonte da plataforma
COPY . .

# Garante que o modelo ML e seu hash SHA-256 estejam atualizados para esta versão do sklearn
RUN python -m ml.treinar

# Boas práticas de segurança em contêineres: executa como usuário sem privilégios (não-root)
RUN useradd --create-home --shell /bin/bash securapy && \
    mkdir -p /app/saida && \
    chown -R securapy:securapy /app
USER securapy

EXPOSE 5000 9999

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3)" || exit 1

CMD ["python", "main.py"]
