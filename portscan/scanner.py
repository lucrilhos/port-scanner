import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
import argparse
import json
from datetime import datetime

# ============================================================
# Argumentos de linha de comando
# ============================================================
def interpreta_portas(texto):
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fim = parte.split("-", 1)
            inicio, fim = int(inicio), int(fim)
            if inicio > fim:
                raise ValueError(f"intervalo invertido: {parte}")
            portas.update(range(inicio, fim + 1))
            pass
        else:
            portas.add(int(parte))

    for p in portas:
        if not 1 <= p <= 65535:
            raise ValueError(f"porta fora do intervalo 1-65535: {p}")
    return sorted(portas)


parser = argparse.ArgumentParser(
    description="🔎 Scanner de portas TCP. Uso exclusivo em sistemas próprios ou com autorização."
)
parser.add_argument("alvo", help="IP ou nome do host (ex: scanme.nmap.org)")
parser.add_argument("-p", "--portas", default="1-1024",
                    help="portas a escanear, ex: 22,80,8000-8010 (padrão: 1-1024)")
parser.add_argument("-t", "--threads", type=int, default=100,
                    help="número de threads (padrão: 100)")
parser.add_argument("--timeout", type=float, default=1.0,
                    help="segundos de espera por porta (padrão: 1.0)")

parser.add_argument("--json", metavar="ARQUIVO",
                    help="salva o relatório em JSON no arquivo indicado")
args = parser.parse_args()

try:
    portas = interpreta_portas(args.portas)
except ValueError as erro:
    parser.error(f"portas inválidas: {erro}")

alvo = args.alvo
threads = args.threads
timeout = args.timeout

# ============================================================
# Parte 1 — Resolver o nome do alvo para um IP
# ============================================================
try:
    ip_alvo = socket.gethostbyname(alvo)
except socket.gaierror:
    print(f"Erro: não foi possível resolver '{alvo}'. Cheque o nome e sua conexão.")
    sys.exit(1)

print(f"Alvo: {alvo} ({ip_alvo})")


# ============================================================
# Parte 2 — Verificar o estado de uma porta
# ============================================================
def verifica_porta(ip, porta, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, porta))
            return "ABERTA"
        except ConnectionRefusedError:
            return "FECHADA"   # recusa RST
        except (socket.timeout, TimeoutError):
            return "FILTRADA"  # silencio ate o timeout. provavel firewall
        except OSError:
            return "ERRO"


# ============================================================
# Parte 3.1 — Varredura com threads
# ============================================================

print(f"Escaneando {len(portas)} portas com {threads} threads...\n")
inicio = time.perf_counter()

with ThreadPoolExecutor(max_workers=100) as executor:
    estados = executor.map(lambda p: verifica_porta(ip_alvo, p, timeout), portas)
    resultados = list(zip(portas, estados))

    fim = time.perf_counter()


abertas = sum(1 for _, estado in resultados if estado == "ABERTA")
fechadas = sum(1 for _, estado in resultados if estado == "FECHADA")
filtradas = sum(1 for _, estado in resultados if estado == "FILTRADA")

# ============================================================
# Parte 4 — Identificação de serviço e pega_banner
# ============================================================

def nome_servico(porta):
    try:
        return socket.getservbyname(porta, "tcp")
    except OSError:
        return("desconhecido")

def pega_banner(ip, porta, timeout=2.0):
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            # serviços que falam sem interrupçao do query client
            try:
                dados = s.recv(1024)
            except (socket.timeout, TimeoutError):
                dados = b""

            # o serviço http espera o cliente falar se vier vazio
            if not dados:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    dados = s.recv(1024)
                except (socket.timeout, TimeoutError):
                    dados = b""

            texto = dados.decode(errors="ignore").strip()
            return texto.splitlines()[0] if texto else ""
    except OSError:
        return ""

# ============================================================
# Fase 5 — Relatório e exportação em .json
# ============================================================