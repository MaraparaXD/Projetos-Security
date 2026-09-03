#!/usr/bin/env python3
"""
Security Toolkit - Nível Simples
==================================

Ferramenta CLI com dois módulos:
1. Port Scanner  - varre portas TCP abertas em um host
2. Password Checker - avalia a força de uma senha

Uso:
    python main.py scan <host> [--start PORTA] [--end PORTA]
    python main.py password [senha]
    python main.py            (abre menu interativo)

Exemplos:
    python main.py scan localhost
    python main.py scan 127.0.0.1 --start 1 --end 1000
    python main.py password "MinhaSenh@123"
"""

import argparse
import getpass
import sys

from port_scanner import executar_scan
from password_checker import analisar_senha, formatar_relatorio_senha


def cmd_scan(args):
    print(f"\n🔍 Escaneando {args.host} (portas {args.start}-{args.end})...\n")
    try:
        relatorio, portas = executar_scan(
            host=args.host,
            porta_inicial=args.start,
            porta_final=args.end,
            timeout=args.timeout,
            n_threads=args.threads,
        )
        print(relatorio)
    except ValueError as e:
        print(f"❌ Erro: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrompido pelo usuário.")
        sys.exit(1)


def cmd_password(args):
    if args.senha:
        senha = args.senha
    else:
        senha = getpass.getpass("Digite a senha a ser analisada (não será exibida): ")

    resultado = analisar_senha(senha)
    print()
    print(formatar_relatorio_senha(senha, resultado))


def menu_interativo():
    print("=" * 55)
    print("###### ESCANEADOR DE SENHAS E PORTAS ######")
    print("=" * 55)
    print("1) Escanear portas de um host")
    print("2) Analisar força de uma senha")
    print("3) Sair")
    print("=" * 55)

    escolha = input("Escolha uma opção: ").strip()

    if escolha == "1":
        host = input("Host/IP para escanear (ex: localhost, 127.0.0.1): ").strip()
        inicio = input("Porta inicial [1]: ").strip() or "1"
        fim = input("Porta final [1024]: ").strip() or "1024"
        args = argparse.Namespace(
            host=host, start=int(inicio), end=int(fim), timeout=0.5, threads=100
        )
        cmd_scan(args)

    elif escolha == "2":
        senha = getpass.getpass("Digite a senha (não será exibida): ")
        args = argparse.Namespace(senha=senha)
        cmd_password(args)

    elif escolha == "3":
        print("Até mais! 👋")
        sys.exit(0)

    else:
        print("Opção inválida.")


def main():
    parser = argparse.ArgumentParser(
        description="Security Toolkit - Scanner de portas + Analisador de senhas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="comando")

    # Subcomando: scan
    parser_scan = subparsers.add_parser("scan", help="Escanear portas TCP de um host")
    parser_scan.add_argument("host", help="Host ou IP a ser escaneado")
    parser_scan.add_argument("--start", type=int, default=1, help="Porta inicial (padrão: 1)")
    parser_scan.add_argument("--end", type=int, default=1024, help="Porta final (padrão: 1024)")
    parser_scan.add_argument("--timeout", type=float, default=0.5, help="Timeout por porta em segundos")
    parser_scan.add_argument("--threads", type=int, default=100, help="Número de threads simultâneas")
    parser_scan.set_defaults(func=cmd_scan)

    # Subcomando: password
    parser_pw = subparsers.add_parser("password", help="Analisar força de uma senha")
    parser_pw.add_argument("senha", nargs="?", help="Senha a analisar (opcional, senão pede com input oculto)")
    parser_pw.set_defaults(func=cmd_password)

    args = parser.parse_args()

    if args.comando is None:
        menu_interativo()
    else:
        args.func(args)


if __name__ == "__main__":
    main()
