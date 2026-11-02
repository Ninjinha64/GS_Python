"""
Aplicação Flask: API REST (Módulo D) + Segurança Web e Dashboard (Módulo E).

Cenários cobertos:
- D1: GET /api/alertas?severidade=critica&pagina=1&tamanho=5 (paginado)
- D2: GET /api/ip/185.220.101.1 (eventos + alertas + geo + score ML + explicação LLM)
- D3: POST /api/alertas sem token → 401
- D4: POST /api/alertas com corpo inválido → 400
- D5: GET /api/ip/<id_malformado> → 400 amigável
- E1: Alerta com `<script>alert(1)</script>` exibido escapado no HTML (Jinja2)
- E2: Headers `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
- E3: Login com senha errada e com usuário inexistente → mesma mensagem 401 genérica
- E4: Qualquer rota acessada registra linha de log (OWASP A09)
"""
from datetime import datetime
import logging
import os

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

from alertas import servidor_alertas
from api.auth import exigir_token, gerar_token_jwt, operador_logado_web
from core import coletor, enriquecimento
from db import mongo_repo, mysql_repo
from ia import assistente
import servicos
import settings

logger_acesso = logging.getLogger("securapy.acesso")

MENSAGEM_LOGIN_GENERICA = "Credenciais inválidas."


def _configurar_logger_acesso(caminho_log=None):
    """Configura logger de auditoria de acesso (OWASP A09)."""
    caminho = caminho_log or settings.ARQUIVO_LOG_ACESSO
    pasta = os.path.dirname(caminho)
    if pasta:
        os.makedirs(pasta, exist_ok=True)

    logger_acesso.setLevel(logging.INFO)
    # evita duplicar handlers quando `criar_app` é chamado várias vezes nos testes
    caminhos_atuais = {getattr(h, "baseFilename", None) for h in logger_acesso.handlers}
    if os.path.abspath(caminho) not in caminhos_atuais:
        fh = logging.FileHandler(caminho, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
        logger_acesso.addHandler(fh)


def _paginacao_args():
    """Extrai e valida `pagina` (>=1) e `tamanho` (1..100) da query string."""
    try:
        pagina = int(request.args.get("pagina", "1"))
        tamanho = int(request.args.get("tamanho", "20"))
    except ValueError as e:
        raise ValueError("pagina e tamanho devem ser números inteiros") from e
    if pagina < 1 or not 1 <= tamanho <= 100:
        raise ValueError("pagina deve ser >= 1 e tamanho entre 1 e 100")
    return pagina, tamanho


def criar_app(repo_mongo=None, repo_usuarios=None, popular_inicial=True, iniciar_socket=False):
    """Application Factory do SecuraPy Platform."""
    pasta_web = os.path.join(settings.BASE_DIR, "web")
    app = Flask(
        __name__,
        template_folder=os.path.join(pasta_web, "templates"),
        static_folder=os.path.join(pasta_web, "static"),
    )
    app.secret_key = settings.SECRET_KEY
    app.config["JSON_AS_ASCII"] = False

    _configurar_logger_acesso()

    app.mongo = repo_mongo or mongo_repo.criar_repo()
    app.usuarios = repo_usuarios or mysql_repo.criar_repo()

    # Garante um operador padrão para demonstração/login inicial se configurado
    senha_admin = settings.ADMIN_SENHA or "CyberShield@2026"
    app.usuarios.garantir_admin(settings.ADMIN_EMAIL, senha_admin)

    # Se o banco estiver vazio (ex.: modo mongomock recém-iniciado), popula com os logs
    if popular_inicial and app.mongo.eventos.count_documents({}) == 0:
        try:
            servicos.analisar_logs_padrao(app.mongo, notificar=False)
        except Exception as e:
            logging.getLogger("securapy.api").warning("Ingestão inicial ignorada: %s", e)

    if iniciar_socket:
        servidor_alertas.iniciar_embutido()

    # ------------------------------------------------- Segurança Web (Mód. E)
    @app.after_request
    def _pos_requisicao(resposta):
        # E2: Headers de segurança obrigatórios em todas as respostas
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'"
        )
        resposta.headers["Referrer-Policy"] = "no-referrer"

        # E4: Logging de acesso (OWASP A09)
        ip_cliente = request.remote_addr or "-"
        operador = getattr(g, "operador", None) or session.get("operador") or {}
        ident = operador.get("sub") or operador.get("email") or "anonimo"
        linha = f"ip={ip_cliente} usuario={ident} metodo={request.method} rota={request.path} status={resposta.status_code}"
        logger_acesso.info(linha)
        return resposta

    # ---------------------------------------------- Tratamento de Erros (6.2)
    @app.errorhandler(400)
    def _erro_400(erro):
        desc = getattr(erro, "description", "Requisição inválida.")
        return jsonify({"erro": desc}), 400

    @app.errorhandler(404)
    def _erro_404(_erro):
        return jsonify({"erro": "Recurso não encontrado."}), 404

    @app.errorhandler(405)
    def _erro_405(_erro):
        return jsonify({"erro": "Método HTTP não permitido nesta rota."}), 405

    @app.errorhandler(Exception)
    def _erro_500(erro):
        if isinstance(erro, HTTPException):
            return jsonify({"erro": erro.description}), erro.code
        logging.getLogger("securapy.api").error("Erro interno não tratado: %s", type(erro).__name__)
        # Nunca vaza traceback, SQL, caminhos internos ou segredos
        return jsonify({"erro": "Erro interno do servidor."}), 500

    # ------------------------------------------------------- Rotas API (Mód. D)
    @app.get("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "plataforma": "SecuraPy Platform",
            "mongo_modo": app.mongo.modo,
            "usuarios_modo": app.usuarios.modo,
            "llm_modo": assistente.modo_atual(),
        }), 200

    @app.post("/api/login")
    def api_login():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict):
            return jsonify({"erro": "Corpo JSON inválido."}), 400
        email = dados.get("email")
        senha = dados.get("senha")
        if not email or not senha:
            return jsonify({"erro": MENSAGEM_LOGIN_GENERICA}), 401

        usuario = app.usuarios.autenticar(email, senha)
        if not usuario:
            # E3: mesma mensagem genérica para usuário inexistente ou senha errada
            return jsonify({"erro": MENSAGEM_LOGIN_GENERICA}), 401

        token = gerar_token_jwt(usuario)
        return jsonify({
            "token": token,
            "tipo": "Bearer",
            "operador": {
                "id": usuario["id"],
                "nome": usuario["nome"],
                "email": usuario["email"],
                "nivel_acesso": usuario["nivel_acesso"],
            },
        }), 200

    @app.post("/api/usuarios")
    @exigir_token(nivel_minimo=4)
    def api_criar_usuario():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict):
            return jsonify({"erro": "Corpo JSON inválido."}), 400
        try:
            novo_id = app.usuarios.criar_usuario(
                nome=dados.get("nome", ""),
                email=dados.get("email", ""),
                senha=dados.get("senha", ""),
                nivel_acesso=dados.get("nivel_acesso", 1),
            )
            return jsonify({"id": novo_id, "mensagem": "Usuário criado com sucesso."}), 201
        except mysql_repo.DadosInvalidosError as e:
            return jsonify({"erro": str(e)}), 400
        except mysql_repo.EmailDuplicadoError:
            return jsonify({"erro": "Email já cadastrado."}), 409

    @app.get("/api/eventos")
    def api_listar_eventos():
        try:
            pagina, tamanho = _paginacao_args()
        except ValueError as e:
            return jsonify({"erro": str(e)}), 400

        fonte = request.args.get("fonte")
        if fonte and fonte not in coletor.FONTES_VALIDAS:
            return jsonify({"erro": f"fonte inválida (use {', '.join(coletor.FONTES_VALIDAS)})"}), 400

        ip = request.args.get("ip")
        if ip and not enriquecimento.ip_valido(ip):
            return jsonify({"erro": "IP informado no filtro é inválido."}), 400

        itens, total = app.mongo.buscar_eventos(
            fonte=fonte,
            tipo=request.args.get("tipo"),
            ip=ip,
            inicio=request.args.get("inicio"),
            fim=request.args.get("fim"),
            pagina=pagina,
            tamanho=tamanho,
        )
        return jsonify({
            "pagina": pagina,
            "tamanho": tamanho,
            "total": total,
            "eventos": itens,
        }), 200

    @app.get("/api/alertas")
    def api_listar_alertas():
        try:
            pagina, tamanho = _paginacao_args()
        except ValueError as e:
            return jsonify({"erro": str(e)}), 400

        sev_param = request.args.get("severidade")
        sev = None
        if sev_param:
            sev = mongo_repo.normalizar_severidade(sev_param)
            if not sev:
                return jsonify({"erro": "severidade inválida (use CRITICA, ALTA, MEDIA, BAIXA ou INFO)"}), 400

        ip = request.args.get("ip")
        if ip and not enriquecimento.ip_valido(ip):
            return jsonify({"erro": "IP informado no filtro é inválido."}), 400

        itens, total = app.mongo.buscar_alertas(
            severidade=sev,
            ip=ip,
            origem=request.args.get("origem"),
            inicio=request.args.get("inicio"),
            fim=request.args.get("fim"),
            pagina=pagina,
            tamanho=tamanho,
        )
        return jsonify({
            "pagina": pagina,
            "tamanho": tamanho,
            "total": total,
            "alertas": itens,
        }), 200

    @app.get("/api/alertas/<alerta_id>")
    def api_obter_alerta(alerta_id):
        alerta = app.mongo.obter_alerta(alerta_id)
        if not alerta:
            return jsonify({"erro": "Alerta não encontrado."}), 404
        return jsonify(alerta), 200

    @app.post("/api/alertas")
    @exigir_token()
    def api_criar_alerta():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict):
            return jsonify({"erro": "Corpo JSON obrigatório."}), 400

        ip = dados.get("ip")
        descricao = dados.get("descricao")
        sev = mongo_repo.normalizar_severidade(dados.get("severidade", ""))
        if not ip or not enriquecimento.ip_valido(ip):
            return jsonify({"erro": "Campo 'ip' obrigatório e deve ser um IPv4/IPv6 válido."}), 400
        if not isinstance(descricao, str) or not 3 <= len(descricao.strip()) <= 500:
            return jsonify({"erro": "Campo 'descricao' obrigatório (3 a 500 caracteres)."}), 400
        if not sev:
            return jsonify({"erro": "Campo 'severidade' inválido (CRITICA, ALTA, MEDIA, BAIXA, INFO)."}), 400

        alerta = {
            "timestamp": dados.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "regra_id": str(dados.get("regra_id") or "M001")[:20],
            "regra_nome": str(dados.get("regra_nome") or "Alerta Manual")[:100],
            "severidade": sev,
            "ip": str(ip).strip(),
            "fonte": dados.get("fonte") if dados.get("fonte") in coletor.FONTES_VALIDAS else "manual",
            "descricao": descricao.strip(),
            "linha_original": dados.get("linha_original"),
            "score_risco": float(dados.get("score_risco", 1.0 if sev == "CRITICA" else 0.7)),
        }
        novo_id = app.mongo.criar_alerta(alerta)
        criado = app.mongo.obter_alerta(novo_id)
        return jsonify(criado), 201

    @app.post("/api/analisar")
    @exigir_token()
    def api_analisar():
        dados = request.get_json(silent=True) or {}
        if not isinstance(dados, dict):
            return jsonify({"erro": "Corpo JSON inválido."}), 400
        try:
            if "eventos" in dados or "lote" in dados:
                eventos = servicos.carregar_de_lote(dados.get("eventos") or dados.get("lote"))
            elif "caminho" in dados:
                eventos = servicos.carregar_de_caminho(dados["caminho"])
            else:
                eventos = coletor.carregar_todos_os_logs(settings.PASTA_LOGS)
            resumo = servicos.analisar_eventos(app.mongo, eventos, notificar=True)
            return jsonify(resumo), 200
        except servicos.EntradaInvalidaError as e:
            return jsonify({"erro": str(e)}), 400

    @app.get("/api/ip/<path:ip>")
    def api_buscar_ip(ip):
        # D5: valida formato do IP; se malformado, retorna 400 amigável
        if not enriquecimento.ip_valido(ip):
            return jsonify({"erro": "Endereço IP inválido. Informe um IPv4 ou IPv6 válido."}), 400
        return jsonify(servicos.info_ip(app.mongo, ip)), 200

    @app.post("/api/ia/explicar")
    def api_explicar_evento():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict) or not (dados.get("evento") or dados.get("linha")):
            return jsonify({"erro": "Informe 'evento' (objeto) ou 'linha' (string)."}), 400
        alvo = dados.get("evento") or dados.get("linha")
        return jsonify(assistente.classificar(alvo)), 200

    @app.get("/api/relatorio")
    def api_relatorio():
        return jsonify(servicos.montar_relatorio(app.mongo)), 200

    # ---------------------------------------------- Rotas Web / Dashboard (Mód. E)
    @app.get("/")
    def dashboard():
        ip_busca = (request.args.get("ip") or "").strip()
        sev_filtro = mongo_repo.normalizar_severidade(request.args.get("severidade", ""))
        msg = request.args.get("msg")
        erro_ip = None
        detalhes_ip = None
        if ip_busca:
            if enriquecimento.ip_valido(ip_busca):
                detalhes_ip = servicos.info_ip(app.mongo, ip_busca)
            else:
                erro_ip = "Endereço IP inválido. Digite um IPv4 ou IPv6 válido."

        resumo = app.mongo.resumo()
        top_suspeitos = app.mongo.listar_ameacas(limite=10)
        alertas_recentes, _ = app.mongo.buscar_alertas(severidade=sev_filtro, pagina=1, tamanho=20)
        return render_template(
            "dashboard.html",
            resumo=resumo,
            top_suspeitos=top_suspeitos,
            alertas_recentes=alertas_recentes,
            ip_busca=ip_busca,
            sev_filtro=sev_filtro,
            detalhes_ip=detalhes_ip,
            erro_ip=erro_ip,
            msg=msg,
            operador=operador_logado_web(),
        )

    @app.post("/acao/analisar")
    def acao_analisar_web():
        servicos.analisar_logs_padrao(app.mongo, notificar=True)
        return redirect(url_for("dashboard", msg="Logs analisados, pontuados pelo ML e transmitidos via TCP!"))

    @app.post("/acao/alerta")
    def acao_criar_alerta_web():
        if not operador_logado_web():
            return redirect(url_for("login_web"))
        ip = (request.form.get("ip") or "").strip()
        descricao = (request.form.get("descricao") or "").strip()
        sev = mongo_repo.normalizar_severidade(request.form.get("severidade", "ALTA")) or "ALTA"
        if enriquecimento.ip_valido(ip) and 3 <= len(descricao) <= 500:
            app.mongo.criar_alerta({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "regra_id": "M001",
                "regra_nome": "Alerta Manual (SOC)",
                "severidade": sev,
                "ip": ip,
                "fonte": "manual",
                "descricao": descricao,
                "score_risco": 1.0 if sev == "CRITICA" else 0.75,
            })
            return redirect(url_for("dashboard", msg=f"Alerta manual ({sev}) criado para {ip}!"))
        return redirect(url_for("dashboard", msg="Erro ao criar alerta: verifique o IP e a descrição."))

    @app.route("/login", methods=["GET", "POST"])
    def login_web():
        erro = None
        status = 200
        if request.method == "POST":
            email = request.form.get("email") or ""
            senha = request.form.get("senha") or ""
            usuario = app.usuarios.autenticar(email, senha)
            if usuario:
                session["operador"] = {
                    "id": usuario["id"],
                    "nome": usuario["nome"],
                    "email": usuario["email"],
                    "nivel": usuario["nivel_acesso"],
                }
                return redirect(url_for("dashboard"))
            # E3: mesma mensagem e status 401 para falha de login
            erro = MENSAGEM_LOGIN_GENERICA
            status = 401
        return render_template("login.html", erro=erro, operador=operador_logado_web()), status

    @app.post("/logout")
    def logout_web():
        session.pop("operador", None)
        return redirect(url_for("dashboard"))

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    aplicacao = criar_app(popular_inicial=True, iniciar_socket=True)
    porta = int(os.getenv("PORT", "5000"))
    aplicacao.run(host="0.0.0.0", port=porta, debug=False)
