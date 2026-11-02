# Trabalho Final (GS) — SecuraPy Platform: SIEM como Plataforma de Segurança

> **Referência oficial da atividade:** [fabioBaraDev/coding_for_security — `gs_2semestre.md`](https://github.com/fabioBaraDev/coding_for_security/blob/main/gs_2semestre.md)

| | |
|---|---|
| **Disciplina:** | Coding for Security |
| **Tipo:** | Trabalho Final Prático — Projeto em Grupo |
| **Abrangência:** | 1º e 2º semestres (com **foco no 2º semestre**) |
| **Equipe:** | 3 a 4 integrantes |
| **Peso:** | 40% da nota final |
| **Entrega:** | Código-fonte + Documentação + Apresentação em vídeo |

---

## 1. Cenário

No 1º semestre, a consultoria **CyberShield Ltda.** entregou ao cliente do setor financeiro um **MVP** do **SecuraPy** — um SIEM simplificado em linha de comando, que lia logs de arquivos, aplicava regras, detectava ataques e alertava via socket. O cliente aprovou o MVP e **renovou o contrato**.

Agora o cliente quer mais. O SecuraPy CLI resolveu o problema imediato, mas não escala nem se integra ao restante do ecossistema de TI. A nova demanda é transformar o SecuraPy em uma **plataforma de segurança de verdade**:

- Os eventos e alertas precisam ser **persistidos em banco de dados** (não podem sumir quando o programa fecha).
- Outros sistemas (dashboards, apps, automações) precisam consultar os dados via **API REST**.
- A detecção baseada só em regras fixas deve ser complementada por **machine learning**, que aprende padrões e prioriza alertas.
- Os analistas querem uma **interface web** e explicações em linguagem natural (via **LLM**) para acelerar a triagem.
- Tudo deve ser **empacotado com Docker** para deploy reproduzível.

A equipe de vocês é, de novo, o time de desenvolvimento da CyberShield. O desafio da GS é **evoluir o SecuraPy do 1º semestre para o SecuraPy Platform**, reaproveitando o que já foi construído e aplicando tudo que aprenderam no 2º semestre.

> **Importante — abrangência:** este trabalho abrange **os dois semestres**. A base de coleta, parsing, regras, detecção (brute force, port scan, blacklist) e alertas via socket vem do 1º semestre e **deve ser reaproveitada**. As camadas novas — banco de dados, API Flask, ML, web, Docker e LLM — são o **foco do 2º semestre** e concentram a maior parte da nota.

---

## 2. Arquitetura da Plataforma

O sistema evolui de scripts CLI para uma arquitetura em camadas. Sugestão de organização:

```
securaPy_platform/
├── core/                          # NÚCLEO — reaproveitado do 1º semestre (evoluído)
│   ├── coletor.py                 # Leitura e parsing de logs (1º sem)
│   ├── regras.py                  # Motor de regras configurável (1º sem)
│   ├── detector.py                # Brute force, port scan, blacklist (1º sem)
│   └── enriquecimento.py          # Consulta ipinfo.io + cache (1º sem, melhorado)
│
├── db/                            # PERSISTÊNCIA — 2º sem (Aulas 1-3)
│   ├── mongo_repo.py              # Repositório de eventos/alertas no MongoDB
│   └── mysql_repo.py              # Repositório de usuários/permissões no MySQL
│
├── ml/                            # MACHINE LEARNING — 2º sem (Aulas 4, 12)
│   ├── treinar.py                 # Treina e salva o classificador (joblib)
│   ├── modelo.pkl                 # Modelo persistido
│   └── classificar.py             # Carrega o modelo e classifica/prioriza alertas
│
├── api/                           # API REST — 2º sem (Aulas 6, 7, 10)
│   ├── app.py                     # Aplicação Flask (rotas, validação, segurança)
│   └── auth.py                    # Autenticação por token
│
├── ia/                            # LLM — 2º sem (Aula 13)
│   └── assistente.py              # Triagem e explicação de eventos via LLM (com fallback)
│
├── web/                           # DASHBOARD — 2º sem (Aula 8)
│   └── templates/                 # Páginas HTML (com escape/XSS defendido)
│
├── alertas/                       # TEMPO REAL — 1º semestre
│   ├── servidor_alertas.py        # Servidor TCP de alertas (1º sem)
│   └── cliente_alertas.py         # Console cliente (1º sem)
│
├── logs/                          # Dados de teste (auth.log, firewall.log, web_access.log)
├── config/regras.json             # Regras configuráveis (1º sem)
├── Dockerfile                     # 2º sem (Aula 11)
├── docker-compose.yml             # Sobe app + MongoDB + MySQL juntos
├── requirements.txt
└── README.md                      # Documentação completa
```

---

## 3. Requisitos Detalhados

### MÓDULO A — Núcleo reaproveitado (1º semestre)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| A1 | Carregar os 3 logs | Lista unificada de eventos, campo `fonte` correto |
| A2 | Detectar brute force no `auth.log` | `185.220.101.1` com 10 FAILs (ALTA) |
| A3 | Detectar port scan no `firewall.log` | `185.220.101.1` com 7 portas distintas |
| A4 | Cruzar com blacklist | Interseção retorna os 3 IPs maliciosos conhecidos |

### MÓDULO B — Persistência em Banco de Dados (2º sem — Aulas 1–3)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| B1 | Ingerir os 3 logs no MongoDB | 58 eventos persistidos (23 auth + 17 firewall + 18 web) |
| B2 | Agregação "top 5 IPs por eventos" | `185.220.101.1` no topo |
| B3 | Cadastrar usuário com email duplicado | Erro tratado (não quebra) |
| B4 | Tentar SQL Injection no login (`' OR '1'='1`) | Neutralizado pela parametrização |

### MÓDULO C — Machine Learning para priorização (2º sem — Aulas 4, 12)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| C1 | Treinar e avaliar | Relatório com precisão, recall e F1 impressos |
| C2 | Classificar `185.220.101.1` (10 FAILs + port scan + blacklist) | Score de risco ALTO / rótulo "ataque" |
| C3 | Classificar `192.168.1.10` (tráfego normal interno) | Rótulo "normal" |
| C4 | Verificar integridade do modelo | Hash confere; se alterado, alerta |

### MÓDULO D — API REST (2º sem — Aulas 6, 7, 10)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| D1 | `GET /api/alertas?severidade=critica&pagina=1&tamanho=5` | Alertas críticos paginados |
| D2 | `GET /api/ip/185.220.101.1` | Eventos + alertas + geo + score do IP |
| D3 | `POST /api/alertas` sem token | 401 |
| D4 | `POST /api/alertas` com corpo inválido | 400 |
| D5 | `GET /api/ip/<id_malformado>` | 400 amigável |

### MÓDULO E — Segurança Web e Dashboard (2º sem — Aula 8)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| E1 | Cadastrar alerta com descrição `<script>alert(1)</script>` e exibir | Texto literal na tela, script NÃO executa |
| E2 | Inspecionar headers da resposta | Os 3 headers de segurança presentes |
| E3 | Login com senha errada e com usuário inexistente | Mesma mensagem 401 genérica |
| E4 | Acessar qualquer rota | Linha de log registrada |

### MÓDULO F — Empacotamento com Docker (2º sem — Aula 11)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| F1 | `docker-compose up` | Os 3 serviços sobem e se comunicam |
| F2 | Script de status via SDK | Lista os 3 contêineres como "running" |
| F3 | Acessar a API dentro do compose | Responde 200 |

### MÓDULO G — Assistente com LLM (2º sem — Aula 13)

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| G1 | Classificar `GET /../../etc/passwd` | CRÍTICO (path traversal) com explicação |
| G2 | Classificar acesso interno normal | NORMAL |
| G3 | Sem API key configurada | Usa fallback por regras, não quebra |
| G4 | Entrada com prompt injection | Não é classificada como NORMAL cegamente; saída validada |

---

## 4. Entregáveis e Critérios de Avaliação

| # | Entregável | Descrição |
|---|-----------|-----------|
| 1 | **Código-fonte** | Pasta `securaPy_platform/` completa, com Dockerfile e docker-compose |
| 2 | **README.md** | Integrantes, descrição, arquitetura, como executar (com Docker), dependências, divisão de tarefas por integrante e o que foi reaproveitado do 1º semestre |
| 3 | **Apresentação em vídeo** | 12–18 min, enviada pelo Teams: subir com docker-compose, analisar logs via API, mostrar dashboard, buscar IP, ver score de ML, explicação do LLM e alertas em tempo real com 2 consoles |
| 4 | **Relatório de exemplo** | JSON exportado pela plataforma com os dados de teste |
| 5 | **Modelo treinado** | `modelo.pkl` + hash de integridade + relatório de métricas (precisão/recall/F1) |

### Bônus (até +1,0 ponto extra)

| Bônus | Pontuação |
|-------|-----------|
| **Detecção de anomalias** (Isolation Forest) além das regras | +0,30 |
| **Correlação temporal** (brute force em janela de tempo, não só contagem total) | +0,20 |
| **CI/CD ou testes automatizados** (pytest) para os módulos, como no 1º sem | +0,30 |
| **Autenticação JWT completa** (geração e verificação de token) na API | +0,20 |
