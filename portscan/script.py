import socket

alvo = "192.168.0.247"
port = 8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
resultado = s.connect_ex((alvo, port))

if resultado == 0:
    print(f"Porta {port}: ABERTA")
else:
    print(f"Porta {port}: NÃO aberta (código: {resultado})")