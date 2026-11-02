# SecuraPy Platform — SIEM como Plataforma de Segurança (GS)

**Disciplina:** Coding for Security  
**Consultoria fictícia:** CyberShield Ltda.  
**Abrangência:** 1º e 2º semestres (Núcleo reaproveitado do 1º sem + Persistência, Machine Learning, API REST, Dashboard Seguro, Docker e Assistente LLM do 2º sem).  
**Enunciado Oficial da Atividade:** [`gs_2semestre.md`](./gs_2semestre.md) — [Repositório do Professor (`fabioBaraDev/coding_for_security`)](https://github.com/fabioBaraDev/coding_for_security/blob/main/gs_2semestre.md)

---

## 1. Integrantes e Divisão de Tarefas

| Integrante | GitHub | Responsabilidade na GS | Módulos Entregues |
|---|---|---|---|
| **Gabriel Pinheiro** | [@GabrielPinheiro314](https://github.com/GabrielPinheiro314) | Núcleo (1º sem) + Persistência Poliglota (MongoDB & MySQL) | **Módulo A** (`core/`) e **Módulo B** (`db/`) |
| **Artur** | [@Ninjinha64](https://github.com/Ninjinha64) | Machine Learning (Pipeline, Validação Cruzada, SHA-256, Isolation Forest) | **Módulo C** (`ml/`) |
| **Vitória** | [@vitoresca](https://github.com/vitoresca) | API REST (Flask, Paginação, Filtros, JWT) + Empacotamento Docker | **Módulo D** (`api/`) e **Módulo F** (`Dockerfile`, `docker-compose.yml`, `verificar_docker.py`) |
| **Pedro / Yuri** | [@PellKkj](https://github.com/PellKkj) / [@yuripregeljhoffmann](https://github.com/yuripregeljhoffmann) | Segurança Web & Dashboard (XSS, Headers, OWASP A09) + Assistente LLM & Testes | **Módulo E** (`web/`), **Módulo G** (`ia/`) e Suíte `pytest` (`tests/`) |

*(Ajuste a tabela acima conforme os 3 ou 4 integrantes finais da entrega da turma).*

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
│   └── test_plataforma.py         # 17 testes cobrindo A1..G4 e todos os bônus
│
├── logs/                          # Dados de teste (auth.log, firewall.log, web_access.log)
├── config/regras.json             # 5 regras de detecção configuráveis
├── saida/                         # Relatórios JSON exportados e log de auditoria (acesso.log)
├── servicos.py                    # Camada de orquestração ponta a ponta
├── settings.py                    # Configurações centralizadas via variáveis de ambiente (.env)
├── verificar_docker.py            # MÓDULO F — Script via SDK docker-py para checar os 3 contêineres
├── main.py                        # Ponto de entrada unificado
├── Dockerfile                     # Imagem Python 3.11-slim (usuário não-root + healthcheck)
├── docker-compose.yml             # Orquestra securapy_app + securapy_mongo + securapy_mysql
├── requirements.txt               # Dependências Python
└── .env.example                   # Exemplo de variáveis de ambiente (sem segredos hardcoded)
```

---

## 3. O que foi Reaproveitado do 1º Semestre (CP1) e como Evoluiu

1. **Coletor (`core/coletor.py`):** Manteve os parsers de `auth.log` (23 eventos; a linha 6 malformada é ignorada com segurança sem travar), `firewall.log` (17 eventos) e `web_access.log` (18 eventos), totalizando **58 eventos**. Evoluiu para extrair também campos estruturados (`usuario`, `porta`, `url`, `status`) usados pelo MongoDB e pelo ML.
2. **Motor de Regras (`core/regras.py` e `config/regras.json`):** Manteve as 5 regras (`R001` a `R005`) e a função `classificar_severidade`. Foi refatorado com tabela de despacho por condição (sem duplicação).
3. **Detector (`core/detector.py`):** Manteve `detectar_brute_force` (dict + set de usuários), `detectar_port_scan` (set de portas distintas — detecta as 7 portas de `185.220.101.1`) e `verificar_blacklist` (interseção de `set` `&` retornando os 3 IPs maliciosos presentes nos logs). Ganhou o bônus `detectar_brute_force_janela` (correlação temporal em janela deslizante de 60s).
4. **Enriquecimento (`core/enriquecimento.py`):** Manteve a integração com `ipinfo.io` e o filtro de IPs privados RFC 1918, ganhando validação via `ipaddress` e cache thread-safe com TTL.
5. **Alertas via Socket TCP (`alertas/`):** Manteve o servidor e o console cliente TCP da CP1, corrigindo a formatação do nome da regra, implementando o comando `/historico` (fila circular dos últimos 50 alertas) e integrando o broadcast diretamente ao endpoint `POST /api/analisar`.

> **Nota sobre os dados de teste (`auth.log`):** O arquivo `auth.log` original fornecido na CP1 contém **11** eventos `FAIL` para o IP `185.220.101.1` (e não 10). Como a regra do detector classifica `> 10` tentativas como severidade **ALTA**, o resultado esperado do cenário A2 (`ALTA`) permanece idêntico.

---

## 4. Como Executar a Plataforma

### Opção 1 — Com Docker Compose (Produção / GitHub Codespaces)

Sobe **API + MongoDB 7 + MySQL 8** em rede isolada com um único comando:

```bash
docker compose up --build -d
```

Verificar os 3 contêineres (`securapy_app`, `securapy_mongo`, `securapy_mysql`) e o healthcheck via SDK `docker-py`:

```bash
python verificar_docker.py
```

### Opção 2 — Execução Local (Sem precisar de Docker instalado)

Caso a máquina não possua Docker Desktop, MongoDB ou MySQL instalados localmente, a camada de persistência (`db/mongo_repo.py` e `db/mysql_repo.py`) ativa automaticamente o **fallback transparente** para `mongomock` (em memória) e `SQLite` (com exatamente as mesmas queries parametrizadas):

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. (Opcional) Treinar o modelo de ML e gerar modelo.pkl + modelo.sha256 + metricas.json
python -m ml.treinar

# 3. (Opcional) Rodar o pipeline ponta a ponta no terminal e exportar relatório JSON
python main.py --analisar

# 4. Subir a plataforma completa (API REST + Dashboard Web na porta 5000 + Servidor TCP na 9999)
python main.py
```

Acesse no navegador:
- **Dashboard Web:** `http://127.0.0.1:5000/`
- **Login Operador padrão:** `admin@cybershield.local` / `CyberShield@2026`

Para abrir **2 consoles de alertas em tempo real** (em outros terminais):
```bash
python -m alertas.cliente_alertas
```

---

## 5. Exemplos de Uso da API REST (Módulo D)

### 5.1 Autenticação (Geração de Token JWT)
```bash
curl -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@cybershield.local\",\"senha\":\"CyberShield@2026\"}"
```

### 5.2 Disparar Análise Ponta a Ponta (`POST /api/analisar` — autenticado)
```bash
curl -X POST http://127.0.0.1:5000/api/analisar \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -H "Content-Type: application/json" \
  -d "{\"caminho\":\"logs\"}"
```

### 5.3 Consultar Alertas Críticos Paginados (Cenário D1)
```bash
curl "http://127.0.0.1:5000/api/alertas?severidade=critica&pagina=1&tamanho=5"
```

### 5.4 Investigação 360° de um IP (Cenário D2)
Retorna eventos, alertas, geolocalização (`ipinfo.io`), score de risco do ML, anomalia Isolation Forest e explicação do Assistente LLM:
```bash
curl "http://127.0.0.1:5000/api/ip/185.220.101.1"
```

### 5.5 Cadastrar Alerta Manual (`POST /api/alertas` — autenticado)
```bash
curl -X POST http://127.0.0.1:5000/api/alertas \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"203.0.113.50\",\"severidade\":\"ALTA\",\"descricao\":\"Tentativa de exploração bloqueada\"}"
```

---

## 6. Testes Automatizados (Bônus pytest)

Para validar todos os cenários **A1–A4, B1–B4, C1–C4, D1–D5, E1–E4, F1–F3, G1–G4** e os 4 bônus:

```bash
pytest -v
```

---

## 7. Itens de Bônus Implementados (+1,0 ponto)

- **Detecção de anomalias com Isolation Forest (+0,30):** `ml/anomalias.py` treina um `IsolationForest` sobre o comportamento normal e identifica desvios fora do padrão conhecido.
- **Correlação temporal de Brute Force (+0,20):** `core/detector.py` (`detectar_brute_force_janela`) avalia picos de falhas de login dentro de uma janela móvel de 60 segundos usando `collections.deque`.
- **Suíte de testes automatizados com `pytest` (+0,30):** `tests/test_plataforma.py` cobre todos os módulos e cenários de teste do enunciado.
- **Autenticação JWT completa (+0,20):** `api/auth.py` assina e verifica tokens JWT (`HS256`) com `sub`, `nivel` e expiração (`exp`) em `POST /api/login`.
