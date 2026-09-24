import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

# ============================================================
# Configuração — Alvo '192.168.0.247' & Port '8000'
# ============================================================
alvo = "scanme.nmap.org"
porta_inicial = 1
porta_final = 1024
timeout = 1.0
threads = 100


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

portas = range(porta_inicial, porta_final + 1)

print(f"Escaneando portas {porta_inicial} a {porta_final} com {threads} threads...\n")
inicio = time.perf_counter()

with ThreadPoolExecutor(max_workers=100) as executor:
    estados = executor.map(lambda p: verifica_porta(ip_alvo, p, timeout), portas)
    resultados = list(zip(portas, estados))

    fim = time.perf_counter()

    for porta, estado in resultados:
        if estado == "ABERTA":
            print(f"Porta {porta}: ABERTA")

abertas = sum(1 for _, estado in resultados if estado == "ABERTA")
fechadas = sum(1 for _, estado in resultados if estado == "FECHADA")
filtradas = sum(1 for _, estado in resultados if estado == "FILTRADA")

print(f"\nResumo: {abertas} abertas, {fechadas} fechadas, {filtradas} filtradas")
print(f"Tempo total: {fim - inicio:.1f}s")