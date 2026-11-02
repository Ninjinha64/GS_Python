"""
Repositório de EVENTOS, ALERTAS e AMEAÇAS no MongoDB (Módulo B — Aulas 1–3).

Por que MongoDB aqui? Eventos têm alto volume e schema flexível (cada fonte
tem campos diferentes) — encaixa no modelo de documentos.

Destaques:
- índices em `ip` e `timestamp` (+ índice único em `hash` → ingestão idempotente);
- índice TTL em `ingerido_em` (retenção configurável — Aula 2, seção 2.4);
- filtros por fonte, tipo, IP, período e severidade, com paginação;
- agregações: top IPs, contagem por fonte e por severidade;
- fallback para mongomock quando não há MongoDB (desenvolvimento sem Docker).

Coleções: eventos | alertas | ameacas
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

import settings

logger = logging.getLogger("securapy.mongo")

NIVEL_SEVERIDADE = {"CRITICA": 5, "ALTA": 4, "MEDIA": 3, "BAIXA": 2, "INFO": 1}


class RepositorioIndisponivel(Exception):
    """Banco fora do ar e fallback desabilitado."""


def _agora():
    return datetime.now(timezone.utc)


def hash_documento(*partes):
    """SHA-256 das partes — identifica um evento/alerta de forma determinística."""
    texto = "|".join("" if p is None else str(p) for p in partes)
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def normalizar_severidade(valor):
    """'crítica', 'critica', 'CRITICA' → 'CRITICA'. Retorna None se inválido."""
    if not isinstance(valor, str):
        return None
    texto = valor.strip().upper().replace("Í", "I").replace("É", "E")
    return texto if texto in NIVEL_SEVERIDADE else None


def conectar_mongo(uri=None, nome_db=None, timeout_ms=2000):
    """
    Conecta ao MongoDB real. Se falhar e o fallback estiver ativo, usa
    mongomock (banco em memória com a mesma API do pymongo).
    Retorna (database, modo) — modo é "mongodb" ou "mongomock".
    """
    uri = uri or settings.MONGO_URI
    nome_db = nome_db or settings.MONGO_DB
    try:
        from pymongo import MongoClient
        cliente = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
        cliente.admin.command("ping")
        logger.info("Conectado ao MongoDB")
        return cliente[nome_db], "mongodb"
    except (ServerSelectionTimeoutError, PyMongoError) as e:
        if not settings.PERMITIR_FALLBACK:
            raise RepositorioIndisponivel("MongoDB indisponível") from e
        logger.warning("MongoDB indisponível (%s). Usando mongomock em memória.", type(e).__name__)
        import mongomock
        return mongomock.MongoClient()[nome_db], "mongomock"


def _serializar(doc):
    """Converte documento do Mongo em dict JSON-friendly (ObjectId → id str)."""
    if doc is None:
        return None
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    for chave, valor in list(doc.items()):
        if isinstance(valor, datetime):
            doc[chave] = valor.isoformat()
    return doc


class MongoRepo:
    """Acesso a dados de eventos, alertas e ameaças."""

    def __init__(self, db, modo="mongodb"):
        self.db = db
        self.modo = modo
        self.eventos = db["eventos"]
        self.alertas = db["alertas"]
        self.ameacas = db["ameacas"]
        self.criar_indices()

    # ------------------------------------------------------------------ setup
    def criar_indices(self):
        """Índices de consulta, unicidade (idempotência) e TTL (retenção)."""
        try:
            for colecao in (self.eventos, self.alertas):
                colecao.create_index([("ip", ASCENDING)])
                colecao.create_index([("timestamp", DESCENDING)])
                colecao.create_index([("hash", ASCENDING)], unique=True)
                colecao.create_index(
                    [("ingerido_em", ASCENDING)],
                    expireAfterSeconds=settings.RETENCAO_DIAS * 86400,
                )
            self.eventos.create_index([("fonte", ASCENDING), ("tipo", ASCENDING)])
            self.alertas.create_index([("sev_nivel", DESCENDING)])
            self.ameacas.create_index([("ip", ASCENDING)], unique=True)
        except PyMongoError as e:
            logger.error("Falha ao criar índices: %s", type(e).__name__)

    def ping(self):
        try:
            self.db.command("ping")
            return True
        except PyMongoError:
            return False
        except Exception:  # mongomock não implementa todos os comandos
            return self.modo == "mongomock"

    # ---------------------------------------------------------------- escrita
    def salvar_eventos(self, eventos):
        """
        Upsert por hash (fonte + linha original): reingerir o mesmo log não
        duplica eventos. Retorna dict {"novos": N, "existentes": M}.
        """
        if not eventos:
            return {"novos": 0, "existentes": 0}
        agora = _agora()
        novos = 0
        for ev in eventos:
            h = hash_documento(ev.get("fonte"), ev.get("linha_original"))
            doc = {k: v for k, v in ev.items() if k != "_id"}
            doc.update(hash=h, ingerido_em=agora)
            res = self.eventos.update_one({"hash": h}, {"$setOnInsert": doc}, upsert=True)
            novos += 1 if res.upserted_id is not None else 0
        return {"novos": novos, "existentes": len(eventos) - novos}

    def salvar_alertas(self, alertas, scores=None):
        """
        Salva alertas (idempotente por hash). `scores` = {ip: score_ml} anexa a
        prioridade do ML em cada alerta. Retorna {"novos": N, "atualizados": M}.
        """
        if not alertas:
            return {"novos": 0, "atualizados": 0}
        scores = scores or {}
        agora = _agora()
        novos = 0
        for al in alertas:
            # alertas do detector são 1 por (regra, IP): sem timestamp no hash,
            # assim reanalisar ATUALIZA o alerta em vez de duplicar
            ts = None if al.get("origem") == "detector" else al.get("timestamp")
            h = al.get("hash") or hash_documento(
                al.get("regra_id"), al.get("ip"), al.get("linha_original"), ts)
            sev = normalizar_severidade(al.get("severidade")) or "INFO"
            doc = {k: v for k, v in al.items() if k not in ("_id", "id")}
            doc.update(hash=h, severidade=sev, sev_nivel=NIVEL_SEVERIDADE[sev],
                       score_risco=round(float(scores.get(al.get("ip"), 0.0)), 4),
                       atualizado_em=agora)
            res = self.alertas.update_one(
                {"hash": h}, {"$set": doc, "$setOnInsert": {"ingerido_em": agora}}, upsert=True)
            novos += 1 if res.upserted_id is not None else 0
        return {"novos": novos, "atualizados": len(alertas) - novos}

    def criar_alerta(self, alerta):
        """Insere um alerta manual (POST /api/alertas). Retorna o id criado."""
        sev = normalizar_severidade(alerta.get("severidade")) or "INFO"
        doc = dict(alerta)
        doc.update(
            severidade=sev, sev_nivel=NIVEL_SEVERIDADE[sev], origem="manual",
            hash=hash_documento("manual", ObjectId()), ingerido_em=_agora(),
            score_risco=float(alerta.get("score_risco", 0.0)),
        )
        return str(self.alertas.insert_one(doc).inserted_id)

    def salvar_ameacas(self, ameacas):
        """Upsert do resumo por IP (detector + score ML)."""
        for am in ameacas:
            self.ameacas.update_one(
                {"ip": am["ip"]},
                {"$set": dict(am, atualizado_em=_agora())},
                upsert=True,
            )
        return len(ameacas)

    def atualizar_scores_alertas(self, scores):
        """Reaplica o score de ML em todos os alertas dos IPs informados."""
        for ip, score in scores.items():
            self.alertas.update_many({"ip": ip}, {"$set": {"score_risco": round(float(score), 4)}})

    # ---------------------------------------------------------------- leitura
    @staticmethod
    def _filtro_periodo(filtro, inicio, fim):
        if inicio or fim:
            filtro["timestamp"] = {}
            if inicio:
                filtro["timestamp"]["$gte"] = inicio
            if fim:
                filtro["timestamp"]["$lte"] = fim

    def buscar_eventos(self, fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                       pagina=1, tamanho=20):
        """Busca eventos com filtros e paginação. Retorna (lista, total)."""
        filtro = {}
        if fonte:
            filtro["fonte"] = fonte
        if tipo:
            filtro["tipo"] = tipo
        if ip:
            filtro["ip"] = ip
        self._filtro_periodo(filtro, inicio, fim)

        total = self.eventos.count_documents(filtro)
        cursor = (self.eventos.find(filtro, {"hash": 0})
                  .sort("timestamp", ASCENDING)
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        return [_serializar(d) for d in cursor], total

    def buscar_alertas(self, severidade=None, ip=None, origem=None, inicio=None, fim=None,
                       pagina=1, tamanho=20):
        """
        Busca alertas ordenados por PRIORIDADE (score de ML desc, depois
        severidade desc). Retorna (lista, total).
        """
        filtro = {}
        if severidade:
            filtro["severidade"] = severidade
        if ip:
            filtro["ip"] = ip
        if origem:
            filtro["origem"] = origem
        self._filtro_periodo(filtro, inicio, fim)

        total = self.alertas.count_documents(filtro)
        cursor = (self.alertas.find(filtro, {"hash": 0})
                  .sort([("sev_nivel", DESCENDING), ("score_risco", DESCENDING), ("ingerido_em", DESCENDING)])
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        return [_serializar(d) for d in cursor], total

    def obter_alerta(self, alerta_id):
        """Retorna o alerta pelo id ou None (id malformado também → None)."""
        try:
            oid = ObjectId(alerta_id)
        except (InvalidId, TypeError):
            return None
        return _serializar(self.alertas.find_one({"_id": oid}, {"hash": 0}))

    def obter_ameaca(self, ip):
        return _serializar(self.ameacas.find_one({"ip": ip}))

    def listar_ameacas(self, limite=10):
        cursor = self.ameacas.find({}).sort([("score_ml", DESCENDING), ("pontuacao", DESCENDING)]).limit(limite)
        return [_serializar(d) for d in cursor]

    def todos_eventos(self):
        """Todos os eventos (para treino do ML / relatório)."""
        return [_serializar(d) for d in self.eventos.find({}, {"hash": 0}).sort("timestamp", ASCENDING)]

    # ------------------------------------------------------------- agregações
    def top_ips(self, limite=5, colecao="eventos"):
        """Top N IPs por quantidade de documentos."""
        pipeline = [
            {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
            {"$sort": {"total": -1, "_id": 1}},
            {"$limit": int(limite)},
        ]
        alvo = self.eventos if colecao == "eventos" else self.alertas
        return [{"ip": d["_id"], "total": d["total"]} for d in alvo.aggregate(pipeline)]

    def contagem_por_fonte(self):
        pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}, {"$sort": {"_id": 1}}]
        return {d["_id"]: d["total"] for d in self.eventos.aggregate(pipeline)}

    def contagem_por_severidade(self):
        pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
        bruto = {d["_id"]: d["total"] for d in self.alertas.aggregate(pipeline)}
        # ordem fixa (CRITICA → INFO) para o dashboard
        return {sev: bruto.get(sev, 0) for sev in NIVEL_SEVERIDADE}

    def resumo(self):
        return {
            "total_eventos": self.eventos.count_documents({}),
            "total_alertas": self.alertas.count_documents({}),
            "eventos_por_fonte": self.contagem_por_fonte(),
            "alertas_por_severidade": self.contagem_por_severidade(),
        }

    def limpar(self):
        """Apaga tudo (usado pelos testes e pela migração com --limpar)."""
        for colecao in (self.eventos, self.alertas, self.ameacas):
            colecao.delete_many({})


def criar_repo():
    """Fábrica: conecta (com fallback) e devolve um MongoRepo pronto."""
    db, modo = conectar_mongo()
    return MongoRepo(db, modo)
