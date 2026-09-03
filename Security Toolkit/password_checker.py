"""
Analisador de força de senha.

Avalia uma senha com base em:
- comprimento
- diversidade de caracteres (minúsculas, maiúsculas, números, símbolos)
- presença em lista de senhas comuns
- padrões óbvios (sequências, repetições)
- entropia estimada (bits) e tempo estimado de brute-force
"""

import math
import re
import os

# Lista curta de senhas extremamente comuns (para fins didáticos).
# Em um projeto real, use uma lista maior tipo rockyou.txt.
SENHAS_COMUNS = {
    "123456", "123456789", "12345678", "password", "senha123", "qwerty",
    "111111", "123123", "abc123", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "senha", "brasil", "flamengo",
    "12345", "1234", "000000", "senha1", "trustno1", "football",
}


def _tem_sequencia(senha, tamanho_min=3):
    """Detecta sequências óbvias tipo 'abcd', '1234', 'qwerty'."""
    senha_lower = senha.lower()

    sequencias = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    for seq in sequencias:
        for i in range(len(seq) - tamanho_min + 1):
            trecho = seq[i:i + tamanho_min]
            if trecho in senha_lower:
                return True
            # também checa a sequência invertida (ex: '4321')
            if trecho[::-1] in senha_lower:
                return True
    return False


def _tem_repeticao(senha, tamanho_min=3):
    """Detecta caracteres repetidos consecutivos, tipo 'aaa' ou '111'."""
    padrao = r"(.)\1{" + str(tamanho_min - 1) + ",}"
    return bool(re.search(padrao, senha))


def _calcular_entropia(senha):
    """
    Estima a entropia em bits com base no tamanho do 'alfabeto' usado
    e no comprimento da senha: entropia = log2(alfabeto^comprimento)
    """
    tem_minuscula = bool(re.search(r"[a-z]", senha))
    tem_maiuscula = bool(re.search(r"[A-Z]", senha))
    tem_numero = bool(re.search(r"[0-9]", senha))
    tem_simbolo = bool(re.search(r"[^a-zA-Z0-9]", senha))

    tamanho_alfabeto = 0
    if tem_minuscula:
        tamanho_alfabeto += 26
    if tem_maiuscula:
        tamanho_alfabeto += 26
    if tem_numero:
        tamanho_alfabeto += 10
    if tem_simbolo:
        tamanho_alfabeto += 32

    if tamanho_alfabeto == 0 or len(senha) == 0:
        return 0.0

    entropia = len(senha) * math.log2(tamanho_alfabeto)
    return entropia


def _estimar_tempo_bruteforce(entropia_bits, tentativas_por_segundo=1e9):
    """
    Estima quanto tempo levaria um ataque de força bruta, assumindo
    1 bilhão de tentativas/segundo (GPU moderna offline).
    """
    combinacoes = 2 ** entropia_bits
    segundos = combinacoes / tentativas_por_segundo

    unidades = [
        ("segundos", 1),
        ("minutos", 60),
        ("horas", 3600),
        ("dias", 86400),
        ("anos", 31536000),
        ("séculos", 3153600000),
    ]

    if segundos < 1:
        return "menos de 1 segundo"

    valor_formatado = segundos
    unidade_escolhida = "segundos"
    for nome, divisor in unidades:
        if segundos / divisor >= 1:
            valor_formatado = segundos / divisor
            unidade_escolhida = nome
        else:
            break

    if valor_formatado > 1e6:
        return f"mais de 1 milhão de {unidade_escolhida}"

    return f"~{valor_formatado:,.1f} {unidade_escolhida}"


def analisar_senha(senha):
    """
    Analisa a senha e retorna um dicionário com:
    - pontuacao: 0 a 100
    - classificacao: Muito Fraca / Fraca / Média / Forte / Muito Forte
    - entropia_bits: float
    - tempo_bruteforce: str
    - problemas: lista de strings com os problemas encontrados
    - sugestoes: lista de strings com sugestões de melhoria
    """
    problemas = []
    sugestoes = []
    pontuacao = 0

    comprimento = len(senha)

    # --- Comprimento ---
    if comprimento == 0:
        return {
            "pontuacao": 0,
            "classificacao": "Inválida",
            "entropia_bits": 0.0,
            "tempo_bruteforce": "instantâneo",
            "problemas": ["Senha vazia."],
            "sugestoes": ["Digite uma senha."],
        }
    elif comprimento < 8:
        problemas.append("Senha muito curta (menos de 8 caracteres).")
        sugestoes.append("Use pelo menos 12 caracteres.")
    elif comprimento < 12:
        pontuacao += 15
        sugestoes.append("Considere usar 12+ caracteres para mais segurança.")
    else:
        pontuacao += 25

    # --- Diversidade de caracteres ---
    tem_minuscula = bool(re.search(r"[a-z]", senha))
    tem_maiuscula = bool(re.search(r"[A-Z]", senha))
    tem_numero = bool(re.search(r"[0-9]", senha))
    tem_simbolo = bool(re.search(r"[^a-zA-Z0-9]", senha))

    variedade = sum([tem_minuscula, tem_maiuscula, tem_numero, tem_simbolo])
    pontuacao += variedade * 10

    if not tem_maiuscula:
        problemas.append("Não contém letra maiúscula.")
        sugestoes.append("Adicione pelo menos uma letra maiúscula.")
    if not tem_minuscula:
        problemas.append("Não contém letra minúscula.")
        sugestoes.append("Adicione pelo menos uma letra minúscula.")
    if not tem_numero:
        problemas.append("Não contém número.")
        sugestoes.append("Adicione pelo menos um número.")
    if not tem_simbolo:
        problemas.append("Não contém símbolo especial (!@#$%...).")
        sugestoes.append("Adicione um símbolo especial.")

    # --- Senha comum ---
    if senha.lower() in SENHAS_COMUNS:
        problemas.append("Esta senha está entre as mais usadas do mundo.")
        sugestoes.append("Evite senhas populares — use uma frase-senha única.")
        pontuacao = min(pontuacao, 10)

    # --- Sequências e repetições ---
    if _tem_sequencia(senha):
        problemas.append("Contém sequência óbvia (ex: abc, 123, qwerty).")
        sugestoes.append("Evite sequências de teclado ou alfabéticas.")
        pontuacao -= 10

    if _tem_repeticao(senha):
        problemas.append("Contém caracteres repetidos em sequência (ex: aaa, 111).")
        sugestoes.append("Evite repetir o mesmo caractere várias vezes seguidas.")
        pontuacao -= 10

    # --- Bônus por comprimento extra ---
    if comprimento >= 16:
        pontuacao += 15

    pontuacao = max(0, min(100, pontuacao))

    # --- Classificação final ---
    if pontuacao < 20:
        classificacao = "Muito Fraca"
    elif pontuacao < 40:
        classificacao = "Fraca"
    elif pontuacao < 65:
        classificacao = "Média"
    elif pontuacao < 85:
        classificacao = "Forte"
    else:
        classificacao = "Muito Forte"

    entropia = _calcular_entropia(senha)
    tempo = _estimar_tempo_bruteforce(entropia)

    if not sugestoes and not problemas:
        sugestoes.append("Ótima senha! Continue usando um gerenciador de senhas.")

    return {
        "pontuacao": pontuacao,
        "classificacao": classificacao,
        "entropia_bits": round(entropia, 1),
        "tempo_bruteforce": tempo,
        "problemas": problemas,
        "sugestoes": sugestoes,
    }


def formatar_relatorio_senha(senha, resultado):
    barra_tamanho = 30
    preenchido = int(barra_tamanho * resultado["pontuacao"] / 100)
    barra = "█" * preenchido + "░" * (barra_tamanho - preenchido)

    linhas = []
    linhas.append("=" * 55)
    linhas.append("  ANÁLISE DE FORÇA DE SENHA")
    linhas.append("=" * 55)
    linhas.append(f"Senha analisada: {'*' * len(senha)}")
    linhas.append(f"Pontuação:       {resultado['pontuacao']}/100  [{barra}]")
    linhas.append(f"Classificação:   {resultado['classificacao']}")
    linhas.append(f"Entropia:        {resultado['entropia_bits']} bits")
    linhas.append(f"Tempo p/ quebrar (força bruta, offline): {resultado['tempo_bruteforce']}")
    linhas.append("-" * 55)

    if resultado["problemas"]:
        linhas.append("Problemas encontrados:")
        for p in resultado["problemas"]:
            linhas.append(f"  ✗ {p}")
    else:
        linhas.append("Nenhum problema óbvio encontrado.")

    linhas.append("")
    linhas.append("Sugestões:")
    for s in resultado["sugestoes"]:
        linhas.append(f"  → {s}")

    linhas.append("=" * 55)
    return "\n".join(linhas)
