# Ajuste visual — São Luis Fidelidade

## O que mudou

| Arquivo | O que é |
|---|---|
| `templates/splash.html` | **Substitui** o arquivo atual. Visual novo (claro, comercial), mas mantém os mesmos botões/links (`/cadastro`, `/login`, `/terminal`). Nada de rota, banco ou lógica foi tocado. |
| `templates/beneficios.html` | **Novo arquivo.** Página com os 10 benefícios do programa. |
| `templates/planos.html` | **Novo arquivo.** Página de planos e preços (plano principal + opcionais WhatsApp/E-commerce). |

Nenhum outro arquivo foi alterado: `base.html`, `login.html`, `cadastro.html`, `cliente.html`, `dono.html`, `terminal.html`, `qr_scan.html`, `recuperar_senha.html`, `404.html`, `offline.html` continuam exatamente como estavam. Banco de dados, autenticação e `/api/*` não foram tocados.

## Passo 1 — Copiar os arquivos

No seu projeto, na pasta `templates/`:

```bash
cd ~/Desktop/saoluis-fidelidade-Serv
# substitui a splash.html atual
cp /caminho/para/splash.html templates/splash.html
# adiciona as 2 páginas novas
cp /caminho/para/beneficios.html templates/beneficios.html
cp /caminho/para/planos.html templates/planos.html
```

## Passo 2 — Adicionar as 2 rotas novas no `app.py`

Abra o `app.py`, encontre este trecho (por volta da linha 569):

```python
@app.route("/cadastro")
def cadastro_page():
    return render_template("cadastro.html")

@app.route("/offline")
def offline():
    return render_template("offline.html")
```

E adicione **logo abaixo** (sem apagar nada):

```python
@app.route("/beneficios")
def beneficios_page():
    return render_template("beneficios.html")

@app.route("/planos")
def planos_page():
    return render_template("planos.html")
```

Ficando assim:

```python
@app.route("/cadastro")
def cadastro_page():
    return render_template("cadastro.html")

@app.route("/offline")
def offline():
    return render_template("offline.html")

@app.route("/beneficios")
def beneficios_page():
    return render_template("beneficios.html")

@app.route("/planos")
def planos_page():
    return render_template("planos.html")
```

## Passo 3 — Testar localmente

```bash
python app.py
```

Depois acesse no navegador:
- `http://localhost:5000/` → nova splash clara
- `http://localhost:5000/beneficios` → página de benefícios
- `http://localhost:5000/planos` → página de planos e preços

Confira também que os fluxos antigos continuam normais:
- `/cadastro`, `/login`, `/terminal` → sem mudança nenhuma
- Login do dono e do cliente → sem mudança

## Passo 4 — Deploy no Render

```bash
git add templates/splash.html templates/beneficios.html templates/planos.html app.py
git commit -m "Ajuste visual: nova splash + páginas de benefícios e planos"
git push
```

## Resumo da entrega

- **Arquivos alterados:** `templates/splash.html` (redesign), `app.py` (2 rotas novas)
- **Arquivos criados:** `templates/beneficios.html`, `templates/planos.html`
- **O que foi melhorado:** visual claro/institucional inspirado nas suas referências, seção de benefícios completa, página de planos e preços com o valor "Encante seu cliente" e os opcionais de WhatsApp/E-commerce, tudo responsivo (mobile, tablet, desktop)
- **Como testar:** ver Passo 3 acima
- **Pendências:** nenhuma no visual. Se você quiser, no futuro dá pra ligar o botão "Falar com a equipe" da página de planos a um formulário ou ao WhatsApp direto — hoje ele leva pro `/cadastro` (rota já existente, não criei nada novo pra isso)
