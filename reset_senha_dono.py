# -*- coding: utf-8 -*-
"""
reset_senha_dono.py
Reseta a senha do usuario DONO direto no banco (SQLite local ou PostgreSQL no Render),
usando as mesmas funcoes de hash do proprio app.py. Nao altera nenhum outro arquivo.

COMO USAR:
1. Coloque este arquivo na RAIZ do projeto (mesma pasta do app.py)
2. Rode:  python reset_senha_dono.py
3. Siga as perguntas na tela (email do dono + nova senha)

Funciona tanto local (usa data/saoluis.db) quanto no Render (se a variavel
DATABASE_URL estiver configurada no ambiente onde voce rodar).
"""

import sys
from app import (
    db_get_user_by_email, db_save_user, hash_pw, USE_PG, SQLITE_FILE
)

def main():
    print("=" * 55)
    print(" RESET DE SENHA — São Luis Fidelidade")
    print("=" * 55)
    print(f"Banco em uso: {'PostgreSQL (Render)' if USE_PG else f'SQLite local ({SQLITE_FILE})'}")
    print()

    email = input("Email do DONO a resetar [dono@saoluis.com.br]: ").strip()
    if not email:
        email = "dono@saoluis.com.br"

    user = db_get_user_by_email(email)
    if not user:
        print(f"\n❌ Nenhum usuário encontrado com o email '{email}'.")
        print("   Confira o email exato cadastrado e tente de novo.")
        sys.exit(1)

    print(f"\n✅ Usuário encontrado: {user.get('name')} (role: {user.get('role')})")
    if user.get("role") != "owner":
        confirma = input("⚠️  Esse usuário NÃO é 'owner'. Continuar mesmo assim? (s/N): ").strip().lower()
        if confirma != "s":
            print("Cancelado.")
            sys.exit(0)

    nova_senha = input("\nNova senha (mínimo 6 caracteres) [saoluis2024]: ").strip()
    if not nova_senha:
        nova_senha = "saoluis2024"
    if len(nova_senha) < 6:
        print("❌ Senha muito curta. Use pelo menos 6 caracteres.")
        sys.exit(1)

    # Atualiza senha + zera bloqueio/tentativas de login
    user["password"] = hash_pw(nova_senha)
    user["failed_attempts"] = 0
    user["locked_until"] = None

    db_save_user(user)

    print("\n" + "=" * 55)
    print("✅ SENHA RESETADA COM SUCESSO!")
    print("=" * 55)
    print(f"Email : {email}")
    print(f"Senha : {nova_senha}")
    print("Conta desbloqueada (tentativas de login zeradas).")
    print("\nJá pode fazer login normalmente em /login → 'Sou Dono'.")

if __name__ == "__main__":
    main()
