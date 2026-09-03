# 🔐 Escaneador de Senha e Portas

>Ferramenta de linha de comando em Python com dois módulos de segurança:

>1. **Scanner de Portas** — varre um host em busca de portas TCP abertas
>2. **Analisador de Senha** — avalia a força de uma senha (entropia, padrões óbvios, senhas comuns)

>Projeto criado para estudo de segurança da informação (redes, sockets, threading e criptografia básica).

## Estrutura

```
escaneador-de-senha-e-portas/
├── main.py               # CLI principal (ponto de entrada)
├── port_scanner.py        # Lógica do scanner de portas
├── password_checker.py    # Lógica do analisador de senha
├── requirements.txt
└── README.md
```

##  Requisitos

- Python 3.8 ou superior
- Nenhuma biblioteca externa é necessária (usa apenas a biblioteca padrão do Python)

## Como usar

### Modo interativo (menu)
```bash
python main.py
```

### Escanear portas
```bash
python main.py scan localhost
python main.py scan 192.168.1.11 --start 1 --end 1000
python main.py scan 192.168.1.11 --start 1 --end 65535 --threads 200
```

| Flag | Descrição | Padrão |
|---|---|---|
| `--start` | primeira porta a testar | 1 |
| `--end` | última porta a testar | 1024 |
| `--timeout` | tempo de espera por porta (s) | 0.5 |
| `--threads` | threads simultâneas | 100 |

### Analisar senha
```bash
python main.py password "MinhaSenha123"
python main.py password          # pede a senha com input oculto (getpass)
```

## 📸 Exemplo de saída

**Scan de portas:**
```
=======================================================
  RELATÓRIO DE SCAN - 192.168.1.11 (192.168.1.11)
=======================================================
Início:   09:27:09
Fim:      09:27:14
Duração:  5.56s
-------------------------------------------------------
PORTA     SERVIÇO             STATUS
-------------------------------------------------------
135       desconhecido        ABERTA
139       desconhecido        ABERTA
445       SMB                 ABERTA
=======================================================
Total de portas abertas: 3
=======================================================
```

**Análise de senha:**
```
=======================================================
  ANÁLISE DE FORÇA DE SENHA
=======================================================
Pontuação:       80/100  [████████████████████████░░░░░░]
Classificação:   Forte
Entropia:        111.4 bits
Tempo p/ quebrar (força bruta, offline): mais de 1 milhão de séculos
=======================================================
```

## O que esse projeto demonstra

- **Sockets TCP** e conexões de rede em baixo nível
- **Threading** para paralelizar varreduras de rede
- **Entropia de senha** e cálculo de tempo estimado de brute-force
- **Regex** para detectar padrões fracos em senhas (sequências, repetições)
- Construção de uma **CLI** completa com `argparse`


##### Este projeto é livre para fins educacionais. #####
