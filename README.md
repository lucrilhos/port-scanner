# 🔎 Port Scanner

Scanner de portas TCP escrito do zero em Python, sem bibliotecas externas. Desenvolvido como projeto de estudo para entender os fundamentos de redes por trás de ferramentas como o Nmap e da fase de enumeração em testes de intrusão.

> ⚠️ **Uso autorizado apenas.** Esta ferramenta foi criada para fins educacionais. Escaneie somente sistemas próprios ou para os quais você tenha autorização explícita. Para praticar, use `127.0.0.1` ou [`scanme.nmap.org`](http://scanme.nmap.org/), servidor mantido pelo projeto Nmap para testes leves.

---

## ✨ Funcionalidades

- **Detecção de estado da porta**: classifica cada porta como aberta, fechada ou filtrada
- **Varredura concorrente** com `ThreadPoolExecutor`, com número de threads configurável
- **Identificação de serviço** pela tabela de portas conhecidas do sistema
- **Banner grabbing**: captura a identificação do serviço, com sondagem HTTP para serviços que não falam primeiro
- **Interface de linha de comando** com portas individuais, intervalos ou os dois combinados
- **Relatório em JSON** com alvo, data, tempo de execução e resultados

---

## ⚙️ Como funciona

O scanner realiza um **TCP connect scan**: tenta completar o *three-way handshake* em cada porta e classifica o resultado pela resposta recebida.

| Estado | Resposta do alvo | Significado |
|---|---|---|
| **Aberta** | SYN-ACK (conexão completa) | Há um serviço escutando na porta |
| **Fechada** | RST (recusa imediata) | O host respondeu, mas nada escuta ali |
| **Filtrada** | Nenhuma resposta até o timeout | Um firewall provavelmente descartou o pacote |

Nas portas abertas, o scanner abre uma nova conexão e lê o que o serviço envia. Serviços como SSH e FTP se identificam assim que a conexão é aberta. Para serviços que esperam o cliente falar primeiro, como HTTP, o scanner envia uma requisição `HEAD` e lê a resposta.

---

## 🚀 Como usar

**Requisitos:** Python 3.8 ou superior. Nenhuma dependência externa.

```bash
git clone https://github.com/lucrilhos/port-scanner.git
cd port-scanner
python3 scanner.py -h
```

### Exemplos

```bash
# Portas 1 a 1024 (padrão)
python3 scanner.py scanme.nmap.org

# Portas específicas e intervalos combinados
python3 scanner.py 127.0.0.1 -p 22,80,443,8000-8010

# Ajustando threads e timeout
python3 scanner.py 127.0.0.1 -p 1-65535 -t 300 --timeout 0.5

# Exportando o relatório em JSON
python3 scanner.py scanme.nmap.org -p 1-1024 --json relatorio.json
```

### Argumentos

| Argumento | Descrição | Padrão |
|---|---|---|
| `alvo` | IP ou nome do host | obrigatório |
| `-p`, `--portas` | Portas a escanear (ex: `22,80,8000-8010`) | `1-1024` |
| `-t`, `--threads` | Número de threads simultâneas | `100` |
| `--timeout` | Segundos de espera por porta | `1.0` |
| `--json ARQUIVO` | Salva o relatório em JSON | desativado |

### Exemplo de saída

```
python3 scanner.py 127.0.0.1 -p 1-6000 -t 75 --timeout 1 --json resultado.json
Alvo: 127.0.0.1 (127.0.0.1)
Escaneando 6000 porta(s) com 75 threads...


PORTA   SERVIÇO       BANNER
------------------------------------------------------------
25      smtp          220 lucrilhos ESMTP Exim 4.98.2 Thu, 24 Sep 2026 1
80      http          HTTP/1.1 200 OK
631     ipp           HTTP/1.0 400 Requisição inválida
3306    mysql         T
5432    postgresql    

Resumo: 5 abertas, 5995 fechadas, 0 filtradas
Tempo de varredura: 0.2s
Relatório salvo em resultado.json

```

---

## 📊 Desempenho

Varredura das portas 1 a 1024 com diferentes quantidades de threads.

| Threads | Tempo |
|---|---|
| 1 | [0.0"] |
| 10 | [0.0"] |
| 100 | [0.1"] |
| 500 | [0.1"] |

A varredura é limitada por I/O: quase todo o tempo é gasto esperando respostas da rede, principalmente em portas filtradas, que consomem o timeout inteiro. Threads permitem que essas esperas aconteçam em paralelo. O ganho diminui a partir de certo ponto, porque o sistema operacional, a rede e o próprio alvo também impõem limites.

---

## ✅ Validação com o Nmap

Os resultados foram comparados com o Nmap, executando o mesmo tipo de varredura (TCP connect) no mesmo alvo e intervalo de portas:

```bash
nmap -sT -p 1-1024 scanme.nmap.org
```

nmap -p 1-1024 127.0.0.1
Starting Nmap 7.95 ( https://nmap.org ) at 2026-09-24 15:12 -03
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000055s latency).
Not shown: 1021 closed tcp ports (conn-refused)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
631/tcp open  ipp

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds


---

## 📚 O que aprendi

- **Handshake TCP na prática:** como SYN, SYN-ACK e RST se traduzem em estados de porta, e por que "sem resposta" é diferente de "recusado"
- **Concorrência em tarefas de I/O:** por que threads funcionam bem aqui mesmo com o GIL do Python, que é liberado enquanto a thread espera a rede
- **Enumeração de serviços:** como o banner grabbing revela software e versão, primeiro passo para relacionar um serviço a vulnerabilidades conhecidas (CVEs)
- **Tratamento de erros de rede:** timeouts, conexões recusadas e falhas de resolução de DNS, com mensagens claras em vez de tracebacks
- **Validação de ferramentas:** comparar os resultados com uma referência consolidada antes de confiar neles

---

## 🗺️ Próximos passos

- [ ] SYN scan ("half-open") com Scapy, montando os pacotes TCP manualmente
- [ ] Suporte a varredura UDP
- [ ] Banner grabbing concorrente para alvos com muitas portas abertas

---

## 👤 Autor

**Lucas M. Moraes**, estudante de Ciência da Computação na FIAP

[GitHub](https://github.com/lucrilhos) · [LinkedIn](https://www.linkedin.com/in/lucas-mendes-473678339/)
