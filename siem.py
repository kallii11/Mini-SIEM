#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mini SIEM - Sistema simples de análise de logs Linux
Detecta eventos suspeitos e gera alertas
"""

import re
import json
import time
import requests
from datetime import datetime
from collections import defaultdict
import os
import sys

class MiniSIEM:
    def __init__(self):
        self.alertas = []
        self.ips_suspeitos = defaultdict(int)
        self.ips_whitelist = ['127.0.0.1', '192.168.1.1']  # IPs confiáveis
        self.comandos_perigosos = [
            'rm -rf', 'dd if=', 'mkfs', 'chmod 777', 
            'wget', 'curl', 'nc -l', 'python -c', 'bash -i',
            'chmod +s', 'chown root'
        ]
        self.usuarios_excluir = []
        self.grupos_excluir = []
        self.cache_geoip = {}
        
    def consultar_geoip(self, ip):
        """Consulta localização do IP usando API gratuita"""
        # Ignora IPs privados
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return {'country': 'Local/Privado', 'estrangeiro': False}
        
        # Verifica cache
        if ip in self.cache_geoip:
            return self.cache_geoip[ip]
        
        try:
            # API gratuita (sem necessidade de chave)
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
            if response.status_code == 200:
                dados = response.json()
                info = {
                    'country': dados.get('country', 'Desconhecido'),
                    'city': dados.get('city', ''),
                    'estrangeiro': dados.get('countryCode') != 'BR'
                }
                self.cache_geoip[ip] = info
                return info
        except:
            pass
        
        return {'country': 'Desconhecido', 'estrangeiro': False}
    
    def analisar_auth_log(self, caminho='/var/log/auth.log'):
        """Analisa o arquivo auth.log"""
        print(f"[*] Analisando {caminho}...")
        
        if not os.path.exists(caminho):
            print(f"[!] Arquivo {caminho} não encontrado")
            return
        
        try:
            with open(caminho, 'r') as f:
                linhas = f.readlines()
        except PermissionError:
            print("[!] Permissão negada. Execute como root ou sudo")
            return
            
        for linha in linhas:
            # Detecta falhas de login SSH
            if 'Failed password' in linha:
                self.detectar_falha_login(linha)
            
            # Detecta login bem-sucedido
            if 'Accepted password' in linha or 'Accepted publickey' in linha:
                self.detectar_login_sucesso(linha)
            
            # Detecta uso de sudo
            if 'sudo:' in linha and 'COMMAND=' in linha:
                self.detectar_sudo(linha)
            
            # Detecta criação de usuário
            if 'new user' in linha or 'useradd' in linha:
                self.detectar_novo_usuario(linha)
            
            # Detecta remoção de usuário
            if 'delete user' in linha or 'userdel' in linha:
                self.detectar_remocao_usuario(linha)
            
            # Detecta criação de grupo
            if 'new group' in linha or 'groupadd' in linha:
                self.detectar_novo_grupo(linha)
            
            # Detecta remoção de grupo
            if 'delete group' in linha or 'groupdel' in linha:
                self.detectar_remocao_grupo(linha)
            
            # Detecta chave SSH inválida
            if 'Invalid user' in linha or 'authentication failure' in linha:
                self.detectar_auth_invalida(linha)
    
    def detectar_falha_login(self, linha):
        """Detecta tentativas de login falhadas"""
        match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', linha)
        if match:
            ip = match.group(1)
            
            # Ignora whitelist
            if ip in self.ips_whitelist:
                return
            
            self.ips_suspeitos[ip] += 1
            
            # Consulta localização do IP
            geoip = self.consultar_geoip(ip)
            
            # Alerta se mais de 5 tentativas
            if self.ips_suspeitos[ip] == 5:
                alerta = {
                    'tipo': 'FORÇA BRUTA',
                    'gravidade': 'ALTA',
                    'ip': ip,
                    'pais': geoip['country'],
                    'estrangeiro': geoip['estrangeiro'],
                    'tentativas': self.ips_suspeitos[ip],
                    'mensagem': f'IP {ip} ({geoip["country"]}) com {self.ips_suspeitos[ip]} tentativas de login falhadas',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                self.alertas.append(alerta)
                print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_login_sucesso(self, linha):
        """Detecta login bem-sucedido fora do horário comercial"""
        hora_atual = datetime.now().hour
        
        # Horário comercial: 8h às 18h
        if hora_atual < 8 or hora_atual > 18:
            match_user = re.search(r'for\s+(\w+)', linha)
            match_ip = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', linha)
            
            usuario = match_user.group(1) if match_user else 'desconhecido'
            ip = match_ip.group(1) if match_ip else 'local'
            
            # Consulta localização se tiver IP
            geoip = {'country': 'Local', 'estrangeiro': False}
            if ip != 'local':
                geoip = self.consultar_geoip(ip)
            
            alerta = {
                'tipo': 'LOGIN FORA DE HORÁRIO',
                'gravidade': 'MÉDIA',
                'usuario': usuario,
                'ip': ip,
                'pais': geoip['country'],
                'mensagem': f'Login de {usuario} às {hora_atual}h de {ip} ({geoip["country"]})',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
            print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_sudo(self, linha):
        """Detecta uso de sudo com comandos perigosos"""
        for cmd in self.comandos_perigosos:
            if cmd in linha:
                match_user = re.search(r'sudo:\s+(\w+)', linha)
                usuario = match_user.group(1) if match_user else 'desconhecido'
                
                alerta = {
                    'tipo': 'COMANDO PERIGOSO',
                    'gravidade': 'ALTA',
                    'usuario': usuario,
                    'comando': cmd,
                    'mensagem': f'Usuário {usuario} executou comando perigoso: {cmd}',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                self.alertas.append(alerta)
                print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_novo_usuario(self, linha):
        """Detecta criação de novos usuários"""
        match = re.search(r'name=(\w+)', linha)
        if not match:
            match = re.search(r'user\s+(\w+)', linha)
        
        if match:
            usuario = match.group(1)
            alerta = {
                'tipo': 'NOVO USUÁRIO',
                'gravidade': 'MÉDIA',
                'usuario': usuario,
                'mensagem': f'Novo usuário criado: {usuario}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
            print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_remocao_usuario(self, linha):
        """Detecta remoção de usuários"""
        match = re.search(r'user\s+(\w+)', linha)
        if match:
            usuario = match.group(1)
            self.usuarios_excluir.append(usuario)
            
            alerta = {
                'tipo': 'USUÁRIO REMOVIDO',
                'gravidade': 'ALTA',
                'usuario': usuario,
                'mensagem': f'Usuário removido: {usuario}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
            print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_novo_grupo(self, linha):
        """Detecta criação de novos grupos"""
        match = re.search(r'group\s+(\w+)', linha)
        if not match:
            match = re.search(r'name=(\w+)', linha)
        
        if match:
            grupo = match.group(1)
            alerta = {
                'tipo': 'NOVO GRUPO',
                'gravidade': 'BAIXA',
                'grupo': grupo,
                'mensagem': f'Novo grupo criado: {grupo}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
            print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_remocao_grupo(self, linha):
        """Detecta remoção de grupos"""
        match = re.search(r'group\s+(\w+)', linha)
        if match:
            grupo = match.group(1)
            self.grupos_excluir.append(grupo)
            
            alerta = {
                'tipo': 'GRUPO REMOVIDO',
                'gravidade': 'MÉDIA',
                'grupo': grupo,
                'mensagem': f'Grupo removido: {grupo}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
            print(f"[!] ALERTA: {alerta['mensagem']}")
    
    def detectar_auth_invalida(self, linha):
        """Detecta tentativas de autenticação inválidas"""
        match_ip = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', linha)
        
        if match_ip:
            ip = match_ip.group(1)
            geoip = self.consultar_geoip(ip)
            
            alerta = {
                'tipo': 'AUTENTICAÇÃO INVÁLIDA',
                'gravidade': 'MÉDIA',
                'ip': ip,
                'pais': geoip['country'],
                'mensagem': f'Tentativa de autenticação inválida de {ip} ({geoip["country"]})',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.alertas.append(alerta)
    
    def analisar_bash_history(self, caminho_home='/home'):
        """Analisa arquivos .bash_history em busca de comandos perigosos"""
        print(f"[*] Analisando .bash_history...")
        
        if not os.path.exists(caminho_home):
            return
        
        for usuario in os.listdir(caminho_home):
            history_path = os.path.join(caminho_home, usuario, '.bash_history')
            
            if os.path.exists(history_path):
                try:
                    with open(history_path, 'r') as f:
                        comandos = f.readlines()
                    
                    for comando in comandos:
                        for cmd_perigoso in self.comandos_perigosos:
                            if cmd_perigoso in comando:
                                alerta = {
                                    'tipo': 'HISTÓRICO SUSPEITO',
                                    'gravidade': 'MÉDIA',
                                    'usuario': usuario,
                                    'comando': comando.strip(),
                                    'mensagem': f'{usuario} tem comando perigoso no histórico',
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                }
                                self.alertas.append(alerta)
                                print(f"[!] ALERTA: {alerta['mensagem']}")
                except:
                    pass
    
    def monitorar_tempo_real(self, caminho='/var/log/auth.log'):
        """Modo live - monitora log em tempo real"""
        print(f"[*] Iniciando monitoramento em tempo real de {caminho}")
        print("[*] Pressione Ctrl+C para parar\n")
        
        if not os.path.exists(caminho):
            print(f"[!] Arquivo {caminho} não encontrado")
            return
        
        try:
            # Vai para o final do arquivo
            with open(caminho, 'r') as f:
                f.seek(0, 2)  # Vai para o final
                
                while True:
                    linha = f.readline()
                    
                    if linha:
                        # Processa a nova linha
                        if 'Failed password' in linha:
                            self.detectar_falha_login(linha)
                        elif 'Accepted password' in linha or 'Accepted publickey' in linha:
                            self.detectar_login_sucesso(linha)
                        elif 'sudo:' in linha and 'COMMAND=' in linha:
                            self.detectar_sudo(linha)
                        elif 'new user' in linha or 'useradd' in linha:
                            self.detectar_novo_usuario(linha)
                        elif 'delete user' in linha or 'userdel' in linha:
                            self.detectar_remocao_usuario(linha)
                        elif 'new group' in linha or 'groupadd' in linha:
                            self.detectar_novo_grupo(linha)
                        elif 'delete group' in linha or 'groupdel' in linha:
                            self.detectar_remocao_grupo(linha)
                    else:
                        time.sleep(1)  # Aguarda 1 segundo
                        
        except KeyboardInterrupt:
            print("\n[*] Monitoramento interrompido pelo usuário")
        except PermissionError:
            print("[!] Permissão negada. Execute como root ou sudo")
    
    def verificar_arquivos_criticos(self):
        """Verifica mudanças em arquivos críticos do sistema"""
        print("[*] Verificando arquivos críticos...")
        
        arquivos_criticos = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers'
        ]
        
        for arquivo in arquivos_criticos:
            if os.path.exists(arquivo):
                try:
                    stat = os.stat(arquivo)
                    mod_time = datetime.fromtimestamp(stat.st_mtime)
                    
                    # Verifica se foi modificado nas últimas 24h
                    diff = datetime.now() - mod_time
                    if diff.total_seconds() < 86400:  # 24 horas
                        alerta = {
                            'tipo': 'ARQUIVO CRÍTICO MODIFICADO',
                            'gravidade': 'ALTA',
                            'arquivo': arquivo,
                            'modificado': mod_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'mensagem': f'Arquivo crítico {arquivo} foi modificado recentemente',
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        self.alertas.append(alerta)
                        print(f"[!] ALERTA: {alerta['mensagem']}")
                except:
                    pass
    
    def gerar_relatorio_txt(self, arquivo='relatorio_siem.txt'):
        """Gera relatório em arquivo texto"""
        print(f"[*] Gerando relatório em {arquivo}...")
        
        with open(arquivo, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("RELATÓRIO MINI SIEM - ANÁLISE DE SEGURANÇA\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total de alertas: {len(self.alertas)}\n\n")
            
            # IPs suspeitos
            f.write("-" * 60 + "\n")
            f.write("IPs SUSPEITOS (tentativas de login)\n")
            f.write("-" * 60 + "\n")
            for ip, tentativas in sorted(self.ips_suspeitos.items(), key=lambda x: x[1], reverse=True):
                geoip = self.consultar_geoip(ip)
                bandeira = " 🚨 ESTRANGEIRO" if geoip['estrangeiro'] else ""
                f.write(f"  {ip}: {tentativas} tentativas - {geoip['country']}{bandeira}\n")
            
            # Alertas por tipo
            f.write("\n" + "-" * 60 + "\n")
            f.write("ALERTAS POR TIPO\n")
            f.write("-" * 60 + "\n")
            
            tipos = defaultdict(int)
            for alerta in self.alertas:
                tipos[alerta['tipo']] += 1
            
            for tipo, count in tipos.items():
                f.write(f"  {tipo}: {count}\n")
            
            # Todos os alertas
            f.write("\n" + "-" * 60 + "\n")
            f.write("DETALHES DOS ALERTAS\n")
            f.write("-" * 60 + "\n\n")
            
            for i, alerta in enumerate(self.alertas, 1):
                f.write(f"{i}. [{alerta['gravidade']}] {alerta['tipo']}\n")
                f.write(f"   {alerta['mensagem']}\n")
                f.write(f"   Timestamp: {alerta['timestamp']}\n\n")
            
            # Recomendações
            f.write("-" * 60 + "\n")
            f.write("RECOMENDAÇÕES DE BLOQUEIO\n")
            f.write("-" * 60 + "\n\n")
            
            for ip, tentativas in self.ips_suspeitos.items():
                if tentativas >= 5:
                    f.write(f"Bloquear IP {ip}:\n")
                    f.write(f"  sudo iptables -A INPUT -s {ip} -j DROP\n\n")
        
        print(f"[✓] Relatório salvo em {arquivo}")
    
    def exportar_json(self, arquivo='alertas_siem.json'):
        """Exporta alertas para JSON"""
        print(f"[*] Exportando alertas para {arquivo}...")
        
        dados = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_alertas': len(self.alertas),
            'ips_suspeitos': dict(self.ips_suspeitos),
            'usuarios_removidos': self.usuarios_excluir,
            'grupos_removidos': self.grupos_excluir,
            'alertas': self.alertas
        }
        
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        
        print(f"[✓] Alertas exportados para {arquivo}")
    
    def sugerir_bloqueios(self):
        """Sugere comandos iptables para bloquear IPs suspeitos"""
        print("\n" + "=" * 60)
        print("SUGESTÕES DE BLOQUEIO DE IPS")
        print("=" * 60 + "\n")
        
        bloqueados = False
        for ip, tentativas in self.ips_suspeitos.items():
            if tentativas >= 5:
                geoip = self.consultar_geoip(ip)
                print(f"[!] IP {ip} ({tentativas} tentativas) - {geoip['country']}")
                print(f"    sudo iptables -A INPUT -s {ip} -j DROP\n")
                bloqueados = True
        
        if not bloqueados:
            print("Nenhum IP necessita bloqueio no momento.\n")
    
    def mostrar_resumo(self):
        """Mostra resumo dos alertas"""
        print("\n" + "=" * 60)
        print("RESUMO DA ANÁLISE")
        print("=" * 60 + "\n")
        print(f"Total de alertas: {len(self.alertas)}")
        print(f"IPs suspeitos monitorados: {len(self.ips_suspeitos)}")
        print(f"Usuários removidos: {len(self.usuarios_excluir)}")
        print(f"Grupos removidos: {len(self.grupos_excluir)}")
        
        if self.alertas:
            print("\nAlertas por gravidade:")
            gravidades = defaultdict(int)
            for alerta in self.alertas:
                gravidades[alerta['gravidade']] += 1
            
            for grav, count in gravidades.items():
                print(f"  {grav}: {count}")


def main():
    """Função principal"""
    print("\n" + "=" * 60)
    print("MINI SIEM - SISTEMA DE ANÁLISE DE LOGS")
    print("=" * 60 + "\n")
    
    # Verifica argumentos
    if len(sys.argv) > 1 and sys.argv[1] == '--live':
        print("Modo: MONITORAMENTO EM TEMPO REAL")
        siem = MiniSIEM()
        siem.monitorar_tempo_real()
        return
    
    print("Modo: ANÁLISE COMPLETA")
    siem = MiniSIEM()
    
    # Análise de logs
    siem.analisar_auth_log()
    siem.analisar_bash_history()
    siem.verificar_arquivos_criticos()
    
    # Exibir resultados
    siem.mostrar_resumo()
    siem.sugerir_bloqueios()
    
    # Gerar relatórios
    siem.gerar_relatorio_txt()
    siem.exportar_json()
    
    print("\n[✓] Análise concluída!")
    print("\nDica: Execute 'sudo python3 mini_siem.py --live' para modo tempo real")


if __name__ == '__main__':
    main()
