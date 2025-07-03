
import re
from datetime import datetime
import requests
import requests
import json



# Leitura e parsing dos logs
with open('/var/log/auth.log', 'r') as f:   #'/var/log/auth.log' — é o caminho do log de autenticação do Linux.
    linhas = f.readlines()  #lê todas as linhas do arquivo e retorna como uma lista de strings (uma linha por item).

alertas = []  # Lista onde os alertas serão armazenados


#Logins fora do horário padrão
def detectar_login_fora_horario(linhas):  
    for linha in linhas:
        if "Accepted password" in linha:
            hora = re.search(r'\w{3}\s+\d+\s+(\d+):(\d+):(\d+)', linha)
            if hora: 
                h = int(hora.group(1))
                if h < 6 or h  > 20:
                    alertas.append({
                        "tipo": "Login fora do horário comercial",
                        "linha": linha.strip()
                        "hora":h
                    })
                    


#Tentativas de login falhadas por IP (brute force)
def detectar_brute_force(linhas):  
    ips = {} #Cria um dicionário vazio chamado ips.
    for linha in linhas:
        if "Failed password" in linha:
            resultado = re.search(r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+):") #Usa uma regex para extrair o IPv4 da linha encontrar o endereço IP de onde a tentativa falhou.
            ip = resultado.group(1)
            if resultado:
                ip = resultado.group(1)
                if ip in ips: #Verifica se o IP já está presente no dicionário ips.
                    ips[ip] += 1 #Se sim, incrementa a contagem.
                else: ips[ip] = 1 #Se não, adiciona o IP com contagem 1.
    for ip, tentativas in ips.items():
        if tentativas > 5:
            alertas.append({
               "tipo": "Possivel tentativa de brute force", 
               "ip": ip,
               "tentativas": tentativas
            })

 


def detectar_criação_de_usuários(linha):
    if "useradd" in linha or "new user" in linha:
        print(f"[Alerta] Novo usuário criado: {linha.strip()}")



def detectar_uso_de_sudo(linha):
    if "sudo:" in linha:
        print(f"[Alerta] Uso de sudo: {linha.strip()}")


def detectar_login_estrangeiro(ips): 
 for ip in ips:
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            pais = res.json().get('countryCode')
            if pais != "BR":
                print(f"[Alerta] Login de IP estrangeiro ({pais}): {ip}")
        except:
            print(f"[Erro] Falha ao consultar GeoIP para {ip}")



def bloquear_ip(ip): ...


#detectar criação de user
def detectar_criacao_de_usuarios(linha):
    if "useradd" in linha or "new user" in linha: #verifica se as expressões existem dentro da variável
        alertas.append({       # método de listas que adiciona um novo item no final da lista.
            "tipo": "Criação de usuário",
            "linha": linha.stip()
        })

#detectar uso de sudo
def detectar_uso_de_sudo(linha):
    if "sudo" in linha:
        alertas.append({
            "tipo": "uso de sudo",
            "linha": linha.strip()
        })



with open('relatorio.json', 'w') as f:
    json.dump(alertas, f, indent=4)

