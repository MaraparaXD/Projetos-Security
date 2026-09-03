"""
Port Scanner simples usando sockets TCP.

Varre um host em busca de portas abertas, tentando conectar em cada
uma delas com timeout curto. Usa threads para acelerar o processo.
"""

import socket
import threading
from queue import Queue
from datetime import datetime

# Portas comuns e seus serviços associados (só para exibição)
PORTAS_CONHECIDAS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class PortScanner:
    def __init__(self, host, porta_inicial=1, porta_final=1024, timeout=0.5, n_threads=100):
        self.host = host
        self.porta_inicial = porta_inicial
        self.porta_final = porta_final
        self.timeout = timeout
        self.n_threads = n_threads
        self.portas_abertas = []
        self.lock = threading.Lock()

    def _resolver_host(self):
        """Resolve o hostname para IP. Levanta erro se não conseguir."""
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            raise ValueError(f"Não foi possível resolver o host: {self.host}")

    def _testar_porta(self, porta):
        """Tenta abrir uma conexão TCP na porta. Se conseguir, a porta está aberta."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            resultado = sock.connect_ex((self.ip, porta))
            if resultado == 0:
                servico = PORTAS_CONHECIDAS.get(porta, "desconhecido")
                with self.lock:
                    self.portas_abertas.append((porta, servico))
        except socket.error:
            pass
        finally:
            sock.close()

    def _worker(self, fila):
        while not fila.empty():
            porta = fila.get()
            self._testar_porta(porta)
            fila.task_done()

    def escanear(self, callback_progresso=None):
        """Executa o scan e retorna a lista de portas abertas ordenada."""
        self.ip = self._resolver_host()
        fila = Queue()

        for porta in range(self.porta_inicial, self.porta_final + 1):
            fila.put(porta)

        total_portas = self.porta_final - self.porta_inicial + 1
        threads = []
        for _ in range(min(self.n_threads, total_portas)):
            t = threading.Thread(target=self._worker, args=(fila,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.portas_abertas.sort(key=lambda x: x[0])
        return self.portas_abertas


def formatar_relatorio(host, ip, portas_abertas, inicio, fim, duracao):
    linhas = []
    linhas.append("=" * 55)
    linhas.append(f"  RELATÓRIO DE SCAN - {host} ({ip})")
    linhas.append("=" * 55)
    linhas.append(f"Início:   {inicio.strftime('%H:%M:%S')}")
    linhas.append(f"Fim:      {fim.strftime('%H:%M:%S')}")
    linhas.append(f"Duração:  {duracao:.2f}s")
    linhas.append("-" * 55)

    if portas_abertas:
        linhas.append(f"{'PORTA':<10}{'SERVIÇO':<20}{'STATUS'}")
        linhas.append("-" * 55)
        for porta, servico in portas_abertas:
            linhas.append(f"{porta:<10}{servico:<20}ABERTA")
    else:
        linhas.append("Nenhuma porta aberta encontrada no intervalo escaneado.")

    linhas.append("=" * 55)
    linhas.append(f"Total de portas abertas: {len(portas_abertas)}")
    linhas.append("=" * 55)
    return "\n".join(linhas)


def executar_scan(host, porta_inicial=1, porta_final=1024, timeout=0.5, n_threads=100):
    """Função de conveniência: escaneia e já retorna o relatório formatado."""
    scanner = PortScanner(host, porta_inicial, porta_final, timeout, n_threads)
    inicio = datetime.now()
    portas = scanner.escanear()
    fim = datetime.now()
    duracao = (fim - inicio).total_seconds()
    relatorio = formatar_relatorio(host, scanner.ip, portas, inicio, fim, duracao)
    return relatorio, portas
