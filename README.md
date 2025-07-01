# Miini SIEM – Analisador de Logs Linux

Um projeto educacional em desenvolvimento que simula um mini SIEM (Security Information and Event Management) para análise de logs em sistemas Linux. O objetivo é detectar **possíveis incidentes de segurança**, gerar alertas e propor medidas defensivas como **bloqueio de IPs**.

> ⚠️ Projeto em construção. Funcionalidades estão sendo adicionadas gradualmente.

---

## Objetivo

- Fornecer uma ferramenta leve e didática para detectar eventos suspeitos em sistemas Linux, como:
  - Tentativas de login falhadas (força bruta)
  - Logins em horários incomuns
  - Uso de comandos perigosos
  - IPs estrangeiros (planejado)

---

## Tecnologias utilizadas

- Python 3
- Expressões regulares (`re`)
- Manipulação de arquivos e logs (`/var/log/auth.log`)
- `iptables` para bloqueio de IPs (requer root)
- Planejado: GeoIP, Flask, geração de relatórios

---

##  Funcionalidades atuais

✅ Checklist do objetivo de funcionalidades do programa :

- [x] Contagem de tentativas de login falhadas por IP
- [x] Detecção de login bem-sucedido fora do horário comercial
- [ ] Comandos perigosos em `.bash_history` e `auth.log`
- [ ] Modo “live” para acompanhar log em tempo real
- [ ] Detecção de uso do `sudo` com comandos perigosos
- [ ] Sugestão de bloqueio de IPs suspeitos via `iptables`
- [ ] Análise de criação de novos usuários
- [ ] Relatórios em `.txt` ou `.csv`
- [ ] Interface web com Flask
- [ ] Integração com APIs de localização IP (GeoIP)
- [ ] Painel de alertas com gráficos

---

## Como usar

> Recomendado executar com privilégios administrativos (root) para acesso aos logs.

```bash
git clone https://github.com/seu-usuario/siem-lite.git
cd siem-lite
python3 siem.py
