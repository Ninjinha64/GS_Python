# SecuraPy Platform — SIEM como Plataforma de Segurança (GS)

**Disciplina:** Coding for Security  
**Consultoria fictícia:** CyberShield Ltda.  
**Abrangência:** 1º e 2º semestres (Núcleo reaproveitado do 1º sem + Persistência, Machine Learning, API REST, Dashboard Seguro, Docker e Assistente LLM do 2º sem).  
**Enunciado Oficial da Atividade:** [`gs_2semestre.md`](./gs_2semestre.md) — [Repositório do Professor (`fabioBaraDev/coding_for_security`)](https://github.com/fabioBaraDev/coding_for_security/blob/main/gs_2semestre.md)

---

## ⚠️ Aviso Importante: Acione o Docker Primeiro!

> **Para executar a plataforma completa com os bancos reais (MongoDB 7 + MySQL 8.0) em rede isolada, é necessário abrir/iniciar o Docker Desktop (ou o daemon do Docker) ANTES de rodar os comandos de execução.**
>
> 1. Abra o **Docker Desktop** e aguarde o ícone indicar que o motor está ativo (*Engine running*).
> 2. Suba os 3 serviços integrados (`securapy_app`, `securapy_mongo`, `securapy_mysql`) com:
>    ```bash
>    docker compose up --build -d
>    ```
> 3. Confirme que os 3 contêineres estão `running` e que a API responde HTTP 200 usando o script de verificação via SDK `docker-py`:
>    ```bash
>    python verificar_docker.py
>    ```
>
> *(Nota de contingência: caso o sistema seja executado em um ambiente de testes sem o Docker acionado, a camada de dados ativa automaticamente o modo de fallback local com `mongomock` + `SQLite` parametrizado para que nenhuma funcionalidade ou teste quebre).*

---

## 1. Integrantes e Divisão de Tarefas

| Integrante | GitHub | Responsabilidade na GS | Módulos Entregues |
|---|---|---|---|
| **Artur Lima** | [@Ninjinha64](https://github.com/Ninjinha64) | Machine Learning (Pipeline, Validação Cruzada, SHA-256, Isolation Forest) | **Módulo C** (`ml/`) |
| **Gabriel Pinheiro** | [@GabrielPinheiro314](https://github.com/GabrielPinheiro314) | Núcleo (1º sem) + Persistência Poliglota (MongoDB & MySQL) | **Módulo A** (`core/`) e **Módulo B** (`db/`) |
| **Vitória** | [@vitoresca](https://github.com/vitoresca) | API REST (Flask, Paginação, Filtros, JWT) + Empacotamento Docker | **Módulo D** (`api/`) e **Módulo F** (`Dockerfile`, `docker-compose.yml`, `verificar_docker.py`) |
| **Pedro / Yuri** | [@PellKkj](https://github.com/PellKkj) / [@yuripregeljhoffmann](https://github.com/yuripregeljhoffmann) | Segurança Web & Dashboard (XSS, Headers, OWASP A09) + Assistente LLM & Testes | **Módulo E** (`web/`), **Módulo G** (`ia/`) e Suíte `pytest` (`tests/`) |

---

## 2. Arquitetura em Camadas

```text
securaPy_platform/
├── core/                          # MÓDULO A — Núcleo reaproveitado do 1º semestre (evoluído)
│   ├── coletor.py                 # Leitura e parsing de auth.log, firewall.log e web_access.log
│   ├── regras.py                  # Motor de regras configurável (config/regras.json)
│   ├── detector.py                # Brute force (+ janela temporal), port scan e blacklist (dict/set)
│   └── enriquecimento.py          # Consulta ipinfo.io com cache TTL, validação IP e modo offline
│
├── db/                            # MÓDULO B — Persistência Poliglota (Aulas 1–3)
│   ├── mongo_repo.py              # MongoDB: eventos, alertas, ameaças, índices + TTL, agregações
│   ├── mysql_repo.py              # MySQL: CRUD de operadores parametrizado (anti-SQLi) e hash PBKDF2
│   └── migrar.py                  # Script de ingestão inicial dos logs e geração de relatório
│
├── ml/                            # MÓDULO C — Machine Learning para Priorização (Aulas 4, 12)
│   ├── features.py                # Extração padronizada de 8 features comportamentais por IP
│   ├── integridade.py             # Cálculo e verificação SHA-256 antes do joblib.load (hashlib)
│   ├── treinar.py                 # Pipeline(StandardScaler + RandomForest), Stratified 5-Fold CV
│   ├── classificar.py             # Carrega modelo (validando SHA-256) e calcula score de risco (0..1)
│   ├── anomalias.py               # BÔNUS: Isolation Forest para detecção de anomalias desconhecidas
│   ├── modelo.pkl                 # Modelo persistido
│   ├── modelo.sha256              # Hash SHA-256 de integridade do modelo
│   └── metricas.json              # Relatório exportado com precisão, recall, F1 e importâncias
│
├── api/                           # MÓDULO D — API REST & Autenticação (Aulas 6, 7, 10)
│   ├── app.py                     # Rotas REST, paginação, validação, status codes e handlers seguros
│   └── auth.py                    # Autenticação Bearer Token + BÔNUS JWT completo (HS256)
│
├── web/                           # MÓDULO E — Segurança Web e Dashboard (Aula 8)
│   └── templates/
│       ├── dashboard.html         # Resumo por fonte/severidade, Top 10 IPs, busca 360° (auto-escape XSS)
│       └── login.html             # Login de operador endurecido (mensagem genérica anti-enumeração)
│
├── ia/                            # MÓDULO G — Assistente SOC com LLM (Aula 13)
│   └── assistente.py              # Triagem NORMAL/SUSPEITO/CRITICO + defesa Prompt Injection + fallback
│
├── alertas/                       # TEMPO REAL — 1º Semestre Integrado
│   ├── servidor_alertas.py        # Servidor TCP multi-cliente com broadcast e /historico
│   ├── cliente_alertas.py         # Console cliente TCP em tempo real
│   └── publicador.py              # Ponte entre a API/pipeline e o servidor TCP
│
├── tests/                         # BÔNUS — Testes Automatizados (pytest)
│   └── test_plataforma.py         # 19 testes cobrindo A1..G4 e todos os bônus
│
├── logs/                          # Dados de teste (auth.log, firewall.log, web_access.log)
├── config/regras.json             # 5 regras de detecção configuráveis
├── saida/                         # Relatórios JSON exportados e log de auditoria (acesso.log)
├── servicos.py                    # Camada de orquestração ponta a ponta
├── settings.py                    # Configurações centralizadas via variáveis de ambiente (.env)
├── verificar_docker.py            # MÓDULO F — Script via SDK docker-py para checar os 3 contêineres
├── main.py                        # Ponto de entrada unificado
├── gs_2semestre.md                # Enunciado oficial da Global Solution
├── Dockerfile                     # Imagem Python 3.11-slim (usuário não-root + healthcheck)
├── docker-compose.yml             # Orquestra securapy_app + securapy_mongo + securapy_mysql
├── requirements.txt               # Dependências Python
└── .env.example                   # Exemplo de variáveis de ambiente (sem segredos hardcoded)
```

---

## 3. Guia Detalhado: O que cada Arquivo e Função Principal Faz

### Módulo A — Núcleo Reaproveitado do 1º Semestre (`core/` e `alertas/`)

- **`core/coletor.py`** — Leitura e normalização dos 3 arquivos de log em dicionários padronizados:
  - `parsear_linha_auth(linha)`: extrai `timestamp`, `tipo` (`FAIL`/`OK`), `usuario` e `ip` do `auth.log`.
  - `parsear_linha_firewall(linha)`: extrai `proto`, `ip` de origem (`src`), `ip_destino` (`dst`) e `porta` (`dport`) do `firewall.log`.
  - `parsear_linha_web(linha)`: extrai método HTTP (`GET`/`POST`/`DELETE`), `url`, `ip` e `status` do `web_access.log`.
  - `carregar_log(caminho_arquivo, fonte)` e `carregar_todos_os_logs(pasta_logs)`: percorrem a pasta `logs/`, ignoram linhas malformadas com segurança (como a linha 6 do `auth.log`) e retornam a lista unificada de **58 eventos** (`23 auth + 17 firewall + 18 web`).

- **`core/regras.py`** — Motor de regras configurável baseado em `config/regras.json`:
  - `carregar_regras(caminho_config)`: lê as 5 regras (`R001` a `R005`) tratando arquivo inexistente ou JSON inválido.
  - `classificar_severidade(pontuacao)`: converte a nota base (`1..10`) em `CRITICA` ($\ge 9$), `ALTA` ($\ge 7$), `MEDIA` ($\ge 5$), `BAIXA` ($\ge 3$) ou `INFO`.
  - `avaliar_regra(regra, evento)` e `aplicar_regras(eventos, regras)`: avaliam condições de usuário privilegiado (`root`, `admin`, `sa`, `oracle`), porta crítica bloqueada (`22`, `23`, `3389`, `445`, `3306`, `5432`, `1433`), *Path Traversal* (`../`, `/etc/passwd`), *XSS* (`<script>`) e reconhecimento web (`/wp-admin`, `/phpmyadmin`, `/shell.php`).

- **`core/detector.py`** — Correlação de eventos com estruturas `dict`, `set` e `deque`:
  - `detectar_brute_force(eventos, threshold=5)`: agrupa falhas `FAIL` por IP e conjunto (`set`) de usuários tentados; identifica `185.220.101.1` com severidade `ALTA`.
  - `detectar_brute_force_janela(eventos, janela_segundos=60, threshold=5)` (**Bônus +0,20**): correlação temporal usando fila deslizante (`collections.deque`) para achar rajadas de falhas em até 60 segundos.
  - `detectar_port_scan(eventos, threshold=3)`: armazena um `set` de portas distintas bloqueadas por IP no firewall; identifica `185.220.101.1` varrendo **7 portas distintas**.
  - `verificar_blacklist(eventos, blacklist)`: usa interseção de conjuntos (`ips_eventos & set(blacklist)`) para cruzar os logs com a lista de *Threat Intelligence*, retornando os 3 IPs maliciosos presentes (`185.220.101.1`, `91.240.118.172`, `45.33.32.156`).
  - `gerar_resumo_ameacas(...)`: consolida todas as detecções somando pontuações de risco por IP.

- **`core/enriquecimento.py`** — Threat Intelligence e Geolocalização:
  - `ip_valido(ip)` e `eh_ip_privado(ip)`: validam endereços IPv4/IPv6 e identificam redes privadas RFC 1918 (`192.168.x.x`, `10.x.x.x`, `127.x.x.x`) usando o módulo `ipaddress`.
  - `consultar_ip(ip, cache)`: consulta cidade, região, país e organização (`ASN`) na API `ipinfo.io` com cache em memória (TTL de 1h) e tratamento de timeout/erros de rede.

- **`alertas/servidor_alertas.py`, `cliente_alertas.py` e `publicador.py`** — Tempo Real via Socket TCP:
  - `ServidorAlertas.iniciar()`: abre o servidor TCP multi-thread na porta `9999` (para consoles de analistas) e porta `9998` (ingestão local).
  - `ServidorAlertas.broadcast_alerta(alerta)`: transmite alertas `CRITICA` e `ALTA` em tempo real para todos os consoles conectados e guarda os últimos 50 alertas no comando `/historico`.

---

### Módulo B — Persistência em Banco de Dados (`db/`)

- **`db/mongo_repo.py`** — Repositório NoSQL (`MongoRepo`) para Eventos, Alertas e Ameaças:
  - `criar_indices()`: cria índices em `ip` e `timestamp`, índice único em `hash` (SHA-256 para ingestão idempotente sem duplicatas) e índice TTL em `ingerido_em`.
  - `salvar_eventos(eventos)` e `salvar_alertas(alertas, scores)`: persistem os 58 eventos e 40 alertas anexando o `score_risco` calculado pelo Machine Learning.
  - `buscar_eventos(...)` e `buscar_alertas(...)`: consultas com filtros combinados (`fonte`, `tipo`, `severidade`, `ip`, `inicio`, `fim`) e paginação (`skip`/`limit`).
  - `top_ips(limite=5)`, `contagem_por_fonte()` e `contagem_por_severidade()`: pipelines de agregação (`$group`, `$sort`, `$limit`) do MongoDB.

- **`db/mysql_repo.py`** — Repositório Relacional (`UsuarioRepo`) para Operadores e Permissões:
  - `criar_tabela()`: cria a tabela `usuarios` com `email UNIQUE` e `CHECK (nivel_acesso BETWEEN 1 AND 5)`.
  - `criar_usuario(nome, email, senha, nivel_acesso)`: valida entradas, aplica hash `PBKDF2-SHA256` (`werkzeug.security`) na senha e executa `INSERT` **100% parametrizado** (`%s` / `?`), tratando e-mail duplicado com `EmailDuplicadoError`.
  - `autenticar(email, senha)`: consulta parametrizada imune a **SQL Injection** (`' OR '1'='1` é neutralizado) e verificação de hash em tempo constante contra enumeração de usuários.

- **`db/migrar.py`** — Script de Migração Inicial:
  - Lê os arquivos da pasta `logs/` através do núcleo, executa o pipeline de análise, popula o MongoDB e exporta o relatório JSON inicial.

---

### Módulo C — Machine Learning para Priorização (`ml/`)

- **`ml/features.py`**:
  - `extrair_features(eventos, blacklist, regras)`: transforma o histórico de cada IP em um vetor numérico de 8 colunas (`fails_auth`, `logins_ok`, `portas_distintas`, `bloqueios_fw`, `web_erros`, `web_total`, `alertas_regra`, `em_blacklist`).

- **`ml/treinar.py`**:
  - `treinar()`: combina os IPs reais dos logs com perfis sintéticos de ataque/normal, treina um `Pipeline(StandardScaler + RandomForestClassifier)`, executa validação cruzada estratificada de 5 folds (**Precision = 0.9836, Recall = 0.9641, F1 = 0.9737**), salva `ml/modelo.pkl` via `joblib`, grava o hash em `ml/modelo.sha256` e exporta `ml/metricas.json`.

- **`ml/integridade.py`** e **`ml/classificar.py`**:
  - `verificar_integridade(caminho_modelo, caminho_hash)`: recalcula o SHA-256 (`hashlib`) do arquivo `.pkl` e compara com `hmac.compare_digest` **antes** de chamar `joblib.load()`. Se o arquivo tiver sido modificado, lança `ModeloAdulteradoError`.
  - `pontuar(eventos, blacklist, regras)`: atribui a cada IP a probabilidade de ataque (`score` de `0.0` a `1.0`), `rotulo` (`ataque`/`normal`) e `nivel` (`ALTO`, `MEDIO`, `BAIXO`).

- **`ml/anomalias.py`** (**Bônus +0,30**):
  - `detectar_anomalias(features_por_ip)`: utiliza `IsolationForest` treinado sobre o tráfego legítimo para identificar anomalias comportamentais desconhecidas.

---

### Módulo D & Módulo E — API REST, Segurança Web e Dashboard (`api/` e `web/`)

- **`api/auth.py`** (**inclui Bônus JWT +0,20**):
  - `gerar_token_jwt(usuario)` e `verificar_token(token)`: geram e validam tokens JWT assinados com `HS256` contendo identificação do operador, nível de acesso e expiração (`exp`).
  - `@exigir_token(nivel_minimo=1)`: decorator que protege as rotas de escrita exigindo `Authorization: Bearer <token>` (retorna HTTP `401` se ausente/inválido).

- **`api/app.py`** e **`web/templates/`**:
  - **Rotas REST:**
    - `POST /api/login`: autentica operador e retorna token Bearer JWT (ou `401` com mensagem genérica anti-enumeração).
    - `GET /api/eventos`: lista eventos filtrados por `fonte`, `tipo`, `ip`, período e paginados (`pagina`, `tamanho`).
    - `GET /api/alertas`, `GET /api/alertas/<id>` e `POST /api/alertas`: listagem paginada por severidade, consulta individual e cadastro autenticado de alertas.
    - `POST /api/analisar`: recebe caminho de log ou lote de eventos, executa Coletor + Regras + Detector + ML, persiste no MongoDB e notifica via socket TCP.
    - `GET /api/ip/<ip>`: visão 360° do IP (eventos + alertas + geolocalização + score ML + anomalia + explicação do LLM); retorna `400` amigável se o IP for malformado.
  - **Segurança Web (Módulo E):**
    - Auto-escape do Jinja2 em `dashboard.html` e `login.html` (qualquer payload `<script>alert(1)</script>` é renderizado como texto literal inofensivo, bloqueando **XSS**).
    - Hook `@app.after_request` que injeta `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` e `Content-Security-Policy` em todas as respostas e grava cada requisição em `saida/acesso.log` (**OWASP A09**).

---

### Módulo F — Empacotamento com Docker (`Dockerfile`, `docker-compose.yml`, `verificar_docker.py`)

- **`Dockerfile`**: empacota a aplicação em `python:3.11-slim`, pré-treina o modelo verificando o hash SHA-256, cria usuário sem privilégios (`securapy` não-root) e configura `HEALTHCHECK`.
- **`docker-compose.yml`**: sobe e conecta em rede (`securapy_net`) os 3 contêineres: `securapy_app` (API/Web/TCP), `securapy_mongo` (MongoDB 7.0) e `securapy_mysql` (MySQL 8.0) com healthchecks.
- **`verificar_docker.py`**:
  - `inspecionar_conteineres()` e `verificar_api_http()`: usam o SDK oficial `docker-py` (`docker.from_env()`) para listar os 3 contêineres como `"running"` e confirmar resposta HTTP `200` da API.

---

### Módulo G — Assistente SOC com LLM (`ia/assistente.py`)

- `anonimizar(texto)`: mascara usuários, senhas, e-mails e IPs privados antes de qualquer envio externo.
- `classificar(entrada)`: classifica eventos ou alertas em `NORMAL`, `SUSPEITO` ou `CRITICO` com explicação curta em português:
  - Se `OPENAI_API_KEY` estiver configurada no ambiente, consulta o modelo com `temperature=0`, saída JSON estrita e delimitadores `<<<DADOS>>>` contra **Prompt Injection**.
  - Valida o rótulo retornado contra o conjunto fixo `{"NORMAL", "SUSPEITO", "CRITICO"}` e aplica um **piso de segurança** (o LLM nunca pode rebaixar para `NORMAL` um ataque já classificado como `CRITICO` ou `SUSPEITO` pelas regras).
  - Caso não haja chave de API ou ocorra falha de rede, aciona automaticamente `classificar_por_regras(entrada)` (fallback determinístico).

---

## 4. Passo a Passo de Execução

### Passo 1 — Com Docker (Recomendado — Inicie o Docker Desktop primeiro!)

```bash
# 1. Certifique-se de que o Docker Desktop está aberto e rodando
# 2. Suba os 3 serviços (App + MongoDB + MySQL)
docker compose up --build -d

# 3. Verifique os 3 contêineres "running" e o status HTTP 200 da API via SDK docker-py
python verificar_docker.py
```

### Passo 2 — Execução Direta via Python (Desenvolvimento / Fallback Local)

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Treinar o modelo de Machine Learning (gera modelo.pkl, modelo.sha256 e metricas.json)
python -m ml.treinar

# 3. Executar ingestão/migração inicial e exportar relatório JSON
python -m db.migrar --relatorio

# 4. Iniciar a plataforma (Dashboard Web + API REST na porta 5000 + Servidor TCP na 9999)
python main.py
```

- **Dashboard Web:** `http://127.0.0.1:5000/`
- **Credenciais de Operador SOC:** `admin@cybershield.local` / `CyberShield@2026`
- **Consoles de Alertas em Tempo Real (abra 2 terminais):**
  ```bash
  python -m alertas.cliente_alertas
  ```

---

## 5. Executando a Suíte de Testes Automatizados (`pytest`)

Todos os cenários do enunciado (**A1–A4, B1–B4, C1–C4, D1–D5, E1–E4, F1–F3, G1–G4**) e os 4 itens de bônus são verificados automaticamente com:

```bash
pytest -v
```
