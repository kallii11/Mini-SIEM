import re
from datetime import datetime
import requests
import requests

# Leitura e parsing dos logs
with open('/var/log/auth.log', 'r') as f:   #'/var/log/auth.log' — é o caminho do log de autenticação do Linux.
    linhas = f.readlines()  #lê todas as linhas do arquivo e retorna como uma lista de strings (uma linha por item).


#Logins bem-sucedidos fora do horário padrão
for linha in linhas:
    if "Accepted password" in linha:
        hora = re.search(r'\w{3}\s+\d+\s+(\d+):(\d+):(\d+') #\w{3} → 3 letras (ex: "Jul") \s+ → espaços \d+ → dia (\d+):(\d+):(\d+) → captura hora, minuto e segundo
        if hora: 
            h = int(hora.group(1))
            if h < 6 or h  > 20:
                print("[Alerta!] Login fora do horário da empresa", linha.strip())


#Tentativas de login falhadas por IP (brute force)
ips = {}
for linha in linhas:
    if "Failed password" in linha:
        resultado = re.search(...)  #Usa regex para extrair o IP da linha
        ip = resultado.group(1)
        if ip in ips:
            ips[ip] += 1 #Se sim, incrementa a contagem.
        else: ips[ip] = 1 #Se não, adiciona o IP com contagem 1.
    for ip, tentativas in ips.items():
        if tentativas > 5:
            print(f"[Alerta] IP {ip} teve {tentativas} tentativas de falhas login")
 

#Logins de IPs internacionais (GeoIP) - dissecar comandos

res = requests.get(f'http://ip-api.com/json/{ip}')
pais = res.json()['countryCode']
if pais != "BR":
    print(f"[Alerta] Login de IP estrangeiro ({pais}): {ip}")

#bloquear ips maliciosos - 

# ip =   # IP a ser bloqueado
#os.system(f"iptables -A INPUT -s {ip} -j DROP")
