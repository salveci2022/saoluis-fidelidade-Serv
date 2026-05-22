# 🛒 São Luis Fidelidade Digital

> Sistema de cartão fidelidade digital para o **Supermercado São Luis** — Santa Maria, Brasília-DF.  
> Clientes acumulam pontos a cada compra e recebem notificações de promoções direto no **WhatsApp**.

---

## 🚀 Demo ao vivo

🔗 **[saoluis-fidelidade-serv.onrender.com](https://saoluis-fidelidade-serv.onrender.com)**

| Perfil | Usuário | Senha |
|--------|---------|-------|
| 👤 Cliente demo | `maria@email.com` | `123456` |
| 🏪 Painel do dono | `dono@saoluis.com.br` | *(via `OWNER_PASSWORD`)* |

---

## 📱 Funcionalidades

### Para o Cliente
- 💳 Cartão digital com nome, número, pontos e nível (Bronze / Prata / Ouro)
- 📊 Barra de progresso e desconto atual (até 10%)
- 🔔 Notificações de promoções em tempo real via WhatsApp
- ⭐ Extrato de pontos por compra
- 📱 QR Code pessoal para mostrar na caixa
- 🔐 Recuperação de senha pelo WhatsApp (código de 6 dígitos)
- 📲 PWA — instala como app no celular (Android e iOS)

### Para o Dono
- 📊 Dashboard com totais de clientes, compras e níveis
- 📣 Envio de promoções em massa via WhatsApp (todos / Prata+Ouro / só Ouro)
- 👥 Lista completa de clientes com pontos e desconto
- ➕ Adicionar pontos manualmente por cliente
- 🖥️ Terminal de autoatendimento (`/terminal`) — cliente informa telefone e valor da compra
- 🔒 Log de auditoria completo (todas as ações registradas)
- ⚙️ Configurações do mercado (nome, endereço, pontos por real)

---

## 🔐 Segurança

Este sistema foi desenvolvido com foco em segurança de produção:

| Proteção | Implementação |
|----------|--------------|
| 🔑 Senhas | `pbkdf2:sha256` com salt via Werkzeug (não SHA-256 puro) |
| 🚫 Brute-force | Bloqueio após 5 tentativas por 15 minutos |
| ⏱️ Rate limiting | Flask-Limiter: 5/min no login, 3/min no cadastro |
| 🛡️ Headers HTTP | `X-Frame-Options`, `X-Content-Type-Options`, `HSTS`, `CSP`, `Referrer-Policy` |
| 🍪 Cookies | `HttpOnly`, `Secure`, `SameSite=Lax` |
| 🔒 HTTPS | Redirecionamento forçado em produção |
| 💉 SQL Injection | 100% queries parametrizadas (sem concatenação) |
| 🖥️ Terminal | PIN verificado no servidor (variável de ambiente) |
| 📋 Auditoria | Todas as ações registradas com IP e timestamp |
| 📱 Recuperação | Códigos persistidos no banco (sobrevivem reinício) |

---

## 🏗️ Arquitetura

```
saoluis-fidelidade-Serv/
├── app.py                  ← Backend Flask completo (único arquivo)
├── requirements.txt        ← Dependências Python
├── Procfile                ← Comando de start para o Render
├── data/
│   └── saoluis.db          ← SQLite (fallback local sem PostgreSQL)
└── templates/
    ├── base.html           ← Layout base + PWA + utilitários JS
    ├── splash.html         ← Página inicial
    ├── login.html          ← Login (cliente / dono)
    ├── cadastro.html       ← Cadastro de novos clientes
    ├── cliente.html        ← App do cliente (cartão, promoções, pontos, QR)
    ├── dono.html           ← Painel do dono
    ├── terminal.html       ← Terminal de autoatendimento
    ├── recuperar_senha.html← Recuperação de senha por WhatsApp
    ├── qr_scan.html        ← Página pública do QR Code
    ├── 404.html            ← Página de erro
    ├── offline.html        ← PWA offline
    └── splash.html         ← Tela inicial animada
```

---

## ⚡ Stack Tecnológico

| Camada | Tecnologia |
|--------|-----------|
| Backend | Python 3 + Flask 3.0 |
| Banco de dados | PostgreSQL (Render) / SQLite (local) |
| Autenticação | Flask Sessions + Werkzeug pbkdf2 |
| Rate limiting | Flask-Limiter |
| WhatsApp | Z-API |
| Deploy | Render.com |
| Frontend | HTML5 + CSS3 + JS vanilla |
| PWA | Service Worker + Web Manifest |

---

## 🛠️ Deploy no Render

### 1. Clonar e subir no GitHub

```bash
git clone https://github.com/salveci2022/saoluis-fidelidade-Serv.git
cd saoluis-fidelidade-Serv
# substitua os arquivos com as versões atualizadas
git add .
git commit -m "feat: segurança aprimorada + README"
git push origin master
```

### 2. Criar Web Service no Render

1. Acesse [render.com](https://render.com) → **New Web Service**
2. Conecte o repositório `saoluis-fidelidade-Serv`
3. Configure:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`

### 3. Variáveis de Ambiente obrigatórias

No Render → **Settings → Environment Variables**:

| Variável | Descrição | Exemplo |
|----------|-----------|---------|
| `SECRET_KEY` | Chave secreta Flask | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `OWNER_PASSWORD` | Senha do painel do dono | `SaoLuis@2025!` |
| `TERMINAL_PIN` | PIN do terminal de autoatendimento | `9876` |
| `DATABASE_URL` | URL do PostgreSQL (gerada pelo Render) | *automático* |
| `ZAPI_INSTANCE` | ID da instância Z-API | `3F15745C...` |
| `ZAPI_TOKEN` | Token Z-API | `1617CE05...` |

### 4. Banco de dados

1. No Render → **New PostgreSQL** → crie o banco
2. Copie a **Internal Database URL**
3. Adicione como `DATABASE_URL` nas variáveis de ambiente
4. O sistema cria as tabelas automaticamente no primeiro deploy

### 5. Manter online (free tier)

Configure o [UptimeRobot](https://uptimerobot.com) para fazer ping a cada 5 minutos:
- **URL:** `https://saoluis-fidelidade-serv.onrender.com`
- **Intervalo:** 5 minutes

---

## 🖥️ Rodando localmente

```bash
# 1. Clonar
git clone https://github.com/salveci2022/saoluis-fidelidade-Serv.git
cd saoluis-fidelidade-Serv

# 2. Ambiente virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Variáveis de ambiente
export SECRET_KEY="chave-local-qualquer"
export OWNER_PASSWORD="senha123"
export TERMINAL_PIN="1234"
export FLASK_DEBUG=1            # desativa HTTPS forçado localmente

# 5. Rodar
python app.py
# Acesse: http://localhost:5000
```

> **Sem `DATABASE_URL`** o sistema usa SQLite automaticamente — perfeito para desenvolvimento local.

---

## 📊 Modelo de Pontos e Descontos

| Pontos acumulados | Nível | Desconto |
|-------------------|-------|----------|
| 0 – 499 | 🥉 Bronze | 0,5% |
| 500 – 999 | 🥉 Bronze | 1% |
| 1.000 – 1.999 | 🥈 Prata | 2% |
| 2.000 – 2.999 | 🥈 Prata | 4% |
| 3.000 – 3.999 | 🥈 Prata | 6% |
| 4.000 – 4.999 | ⭐ Ouro | 8% |
| 5.000+ | ⭐ Ouro | 10% |

> **Regra padrão:** 1 ponto por R$ 1,00 gasto (configurável no painel do dono)

---

## 🔗 APIs principais

| Método | Rota | Descrição | Auth |
|--------|------|-----------|------|
| `POST` | `/api/login` | Login cliente ou dono | — |
| `POST` | `/api/cadastro` | Cadastro de novo cliente | — |
| `GET` | `/api/cliente/me` | Dados do cartão do cliente | ✅ |
| `GET` | `/api/cliente/transactions` | Extrato de pontos | ✅ |
| `GET` | `/api/dono/stats` | Estatísticas do painel | ✅ Owner |
| `GET` | `/api/dono/clientes` | Lista de clientes | ✅ Owner |
| `POST` | `/api/dono/add_points` | Adicionar pontos manualmente | ✅ Owner |
| `POST` | `/api/dono/send_promo` | Enviar promoção por WhatsApp | ✅ Owner |
| `POST` | `/api/terminal/pontuar` | Registrar compra no terminal | PIN |
| `POST` | `/api/recuperar/solicitar` | Solicitar código de recuperação | — |
| `POST` | `/api/recuperar/verificar` | Verificar código e redefinir senha | — |
| `GET` | `/qr/<card>/<token>` | Página pública do QR Code | HMAC |

---

## 📄 Licença

Desenvolvido por **SPYNET Tecnologia Forense & Soluções Digitais Ltda**  
CNPJ: 64.000.808/0001-51 — Brasília-DF  
📧 spynetintelligence@proton.me  
📱 (61) 99396-2090

> Sistema SaaS proprietário. Todos os direitos reservados.  
> Disponível para licenciamento para outros estabelecimentos comerciais.
