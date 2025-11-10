#  Mini SIEM - Security Information and Event Management

Sistema leve e didático de detecção de intrusão para análise de logs em sistemas Linux. Detecta eventos suspeitos, gera alertas e propõe medidas defensivas automaticamente.

Visto que opera em sistemas de uso pessoal sua funcionalidade é apenas a familiarização com alguns tipo de função e procedimentos de checagem

##  Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Tipos de Detecção](#tipos-de-detecção)
- [Exemplos de Output](#exemplos-de-output)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

---

##  Sobre o Projeto

O **Mini SIEM** é uma ferramenta funcional desenvolvida para ajudar a entender um pouco como siems reais operam, contando com funções como:

- Monitorar atividades suspeitas em sistemas Linux
- Detectar tentativas de invasão e força bruta
- Identificar comandos perigosos executados
- Rastrear mudanças em usuários e grupos
- Gerar relatórios detalhados com recomendações de segurança

O projeto oferece duas interfaces: **linha de comando** (para automação) e **interface gráfica** (para visualização intuitiva).

---

## Funcionalidades

###  Detecção de Eventos

- ✅ **Tentativas de login falhadas** (força bruta via SSH)
- ✅ **Login fora do horário comercial** (8h às 18h)
- ✅ **Comandos perigosos** em histórico bash e logs
- ✅ **Criação/remoção de usuários e grupos**
- ✅ **Uso de sudo com comandos críticos**
- ✅ **Tentativas de autenticação inválida**
- ✅ **Modificações em arquivos críticos** (/etc/passwd, /etc/shadow, etc)
- ✅ **Geolocalização de IPs** (detecta acessos estrangeiros)

###  Recursos

- **Relatórios em TXT** - Formato legível para documentação
- **Exportação JSON** - Para integração com outras ferramentas
- **Sugestões automáticas** - Comandos iptables prontos para bloqueio
- **Interface gráfica** - Dashboard com gráficos e métricas
- **Lista branca de IPs** - Evita falsos positivos
- **Cache de GeoIP** - Otimiza consultas de localização

---

##  Pré-requisitos

### Sistema Operacional
- Linux (Ubuntu, Debian, CentOS, Fedora, etc)
- Acesso root ou sudo

### Software
```bash
Python 3.6 ou superior
pip3 (gerenciador de pacotes Python)
```

### Bibliotecas Python
```bash
requests  # Para consultas GeoIP
tkinter   # Para interface gráfica (geralmente já incluso)
```

---

##  Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/mini-siem.git
cd mini-siem
```

### 2. Instale as dependências

```bash
pip3 install requests
```

### 3. Verifique as permissões

O Mini SIEM precisa de privilégios root para ler logs do sistema:

```bash
sudo python3 mini_siem.py
```

---

##  Uso

### Interface de Linha de Comando

#### Análise completa do sistema

```bash
sudo python3 mini_siem.py
```

**Saída:**
- Console com alertas em tempo real
- Arquivo `relatorio_siem.txt` com relatório completo
- Arquivo `alertas_siem.json` com dados estruturados

---

### Interface Gráfica

#### Iniciar a interface

```bash
python3 mini_siem_gui.py
```

**Funcionalidades da GUI:**

1. **Dashboard Principal**
   - Gráfico de pizza com distribuição de alertas
   - Métricas: Total de alertas, IPs suspeitos, comandos perigosos

2. **Console de Execução**
   - Visualização em tempo real da análise
   - Cores para diferentes níveis de severidade

3. **Relatório Detalhado**
   - Aba separada com relatório completo
   - Exportação para TXT/JSON

4. **Ações Recomendadas**
   - Comandos iptables prontos para copiar
   - Lista de IPs para bloqueio

---

##  Tipos de Detecção

### 1. Força Bruta (Alta Gravidade)
Detecta múltiplas tentativas de login falhadas do mesmo IP.

```
Threshold: 5 tentativas
Ação: Alerta + sugestão de bloqueio via iptables
```

### 2. Login Fora de Horário (Média Gravidade)
Identifica logins bem-sucedidos fora do horário comercial.

```
Horário comercial: 8h às 18h
Ação: Alerta com informações do usuário e IP
```

### 3. Comandos Perigosos (Alta Gravidade)
Lista de comandos monitorados:

```python
- rm -rf      # Remoção recursiva
- dd if=      # Cópia de baixo nível
- mkfs        # Formatação de disco
- chmod 777   # Permissões totais
- wget/curl   # Download de arquivos
- nc -l       # Netcat (backdoor)
- python -c   # Código inline
- bash -i     # Shell interativo
- chmod +s    # Bit SUID
- chown root  # Mudança de proprietário
```

### 4. Mudanças em Usuários/Grupos (Média/Alta Gravidade)
- Criação de novos usuários
- Remoção de usuários
- Criação de grupos
- Remoção de grupos

### 5. Arquivos Críticos (Alta Gravidade)
Monitora modificações em:
```
/etc/passwd
/etc/shadow
/etc/group
/etc/sudoers
```

### 6. Geolocalização (Variável)
- Identifica país de origem do IP
- Marca acessos estrangeiros como suspeitos
- Usa API gratuita (ip-api.com)

---

##  Exemplos de Output

### Console (Análise em execução)

```
============================================================
MINI SIEM - SISTEMA DE ANÁLISE DE LOGS
============================================================

[*] Analisando /var/log/auth.log...
[!] ALERTA: IP 192.168.1.50 (Brasil) com 5 tentativas de login falhadas
[!] ALERTA: Login de admin às 22h de 203.0.113.45 (China)
[!] ALERTA: Usuário john executou comando perigoso: rm -rf
[*] Analisando .bash_history...
[*] Verificando arquivos críticos...

============================================================
RESUMO DA ANÁLISE
============================================================
Total de alertas: 8
IPs suspeitos monitorados: 3
Usuários removidos: 0
Grupos removidos: 0

Alertas por gravidade:
  ALTA: 5
  MÉDIA: 3

============================================================
SUGESTÕES DE BLOQUEIO DE IPS
============================================================

[!] IP 192.168.1.50 (8 tentativas) - Brasil
    sudo iptables -A INPUT -s 192.168.1.50 -j DROP

[✓] Relatório salvo em relatorio_siem.txt
[✓] Alertas exportados para alertas_siem.json
[✓] Análise concluída!
```

### Relatório TXT (relatorio_siem.txt)

```
============================================================
RELATÓRIO MINI SIEM - ANÁLISE DE SEGURANÇA
============================================================

Data: 2025-10-28 14:30:00
Total de alertas: 8

------------------------------------------------------------
IPs SUSPEITOS (tentativas de login)
------------------------------------------------------------
  192.168.1.50: 8 tentativas - Brasil
  203.0.113.45: 3 tentativas - China 🚨 ESTRANGEIRO

------------------------------------------------------------
ALERTAS POR TIPO
------------------------------------------------------------
  FORÇA BRUTA: 2
  LOGIN FORA DE HORÁRIO: 2
  COMANDO PERIGOSO: 3
  NOVO USUÁRIO: 1

------------------------------------------------------------
DETALHES DOS ALERTAS
------------------------------------------------------------

1. [ALTA] FORÇA BRUTA
   IP 192.168.1.50 (Brasil) com 8 tentativas de login falhadas
   Timestamp: 2025-10-28 14:25:00

2. [ALTA] COMANDO PERIGOSO
   Usuário john executou comando perigoso: rm -rf
   Timestamp: 2025-10-28 14:20:00

------------------------------------------------------------
RECOMENDAÇÕES DE BLOQUEIO
------------------------------------------------------------

Bloquear IP 192.168.1.50:
  sudo iptables -A INPUT -s 192.168.1.50 -j DROP
```

### JSON (alertas_siem.json)

```json
{
  "timestamp": "2025-10-28 14:30:00",
  "total_alertas": 8,
  "ips_suspeitos": {
    "192.168.1.50": 8,
    "203.0.113.45": 3
  },
  "usuarios_removidos": [],
  "grupos_removidos": [],
  "alertas": [
    {
      "tipo": "FORÇA BRUTA",
      "gravidade": "ALTA",
      "ip": "192.168.1.50",
      "pais": "Brasil",
      "estrangeiro": false,
      "tentativas": 8,
      "mensagem": "IP 192.168.1.50 (Brasil) com 8 tentativas de login falhadas",
      "timestamp": "2025-10-28 14:25:00"
    }
  ]
}
```

---

##  Estrutura do Projeto

```
mini-siem/
│
├── mini_siem.py           # Script principal (backend)
├── mini_siem_gui.py       # Interface gráfica
├── README.md              # Este arquivo
│
├── relatorio_siem.txt     # Relatório gerado (após análise)
├── alertas_siem.json      # Dados estruturados (após análise)
│
└── requirements.txt       # Dependências Python
```

---

##  Configuração Avançada

### Customizar Lista Branca de IPs

Edite o arquivo `mini_siem.py`:

```python
self.ips_whitelist = ['127.0.0.1', '192.168.1.1', 'SEU_IP_AQUI']
```

### Adicionar Comandos Perigosos

```python
self.comandos_perigosos = [
    'rm -rf',
    'dd if=',
    # Adicione seus comandos aqui
    'iptables -F',
    'systemctl stop firewalld'
]
```

### Modificar Horário Comercial

```python
# No método detectar_login_sucesso()
if hora_atual < 8 or hora_atual > 18:  # Mude os valores aqui
```

---

##  Segurança e Privacidade

- O Mini SIEM **NÃO coleta** ou envia dados para servidores externos (exceto consultas GeoIP opcionais)
- Todos os dados são armazenados localmente
- Requer privilégios root apenas para leitura de logs do sistema
- **Recomendação**: Execute em ambientes de teste antes de produção

---

##  Troubleshooting

### Erro: "Permissão negada"
```bash
# Solução: Execute com sudo
sudo python3 mini_siem.py
```

### Erro: "Arquivo /var/log/auth.log não encontrado"
```bash
# Em algumas distribuições, o arquivo pode ter outro nome
# CentOS/RHEL: /var/log/secure
# Edite o caminho no código se necessário
```

### Erro: "ModuleNotFoundError: No module named 'requests'"
```bash
# Instale a dependência
pip3 install requests
```

### Interface gráfica não abre
```bash
# Verifique se tkinter está instalado
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo yum install python3-tkinter  # CentOS/RHEL
```

---

##  Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para:

1. Fazer um Fork do projeto
2. Criar uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abrir um Pull Request

---

##  Roadmap

- [ ] Integração com Fail2Ban
- [ ] Notificações por email/Telegram
- [ ] Dashboard web (Flask/Django)
- [ ] Suporte a múltiplos arquivos de log
- [ ] Análise de logs de firewall
- [ ] Machine Learning para detecção de anomalias
- [ ] Docker container
- [ ] Relatórios em PDF

---

##  Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.



---
