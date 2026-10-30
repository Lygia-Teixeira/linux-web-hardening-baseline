# 01 — Controles de servidor (Linux + cPanel/WHM + Apache)

Controles aplicados **uma vez por servidor**; valem para todos os sites e contas de e-mail hospedados nele.

Formato de cada controle: **Objetivo · Como aplicar · Como verificar · Mapeamento**. Abreviações do mapeamento: CIS = CIS Controls v8 (safeguard); NIST = NIST SP 800-53 Rev. 5; ASVS = OWASP ASVS 4.0.3.

Regra geral para qualquer mudança: **backup do arquivo → mudança → teste de sintaxe → reload → verificação de todos os sites (código HTTP antes/depois) → rollback documentado**.

---

## SRV-01 — TLS: só versões 1.2 e 1.3

- **Objetivo:** eliminar protocolos com fraquezas conhecidas (SSLv3, TLS 1.0, TLS 1.1).
- **Como aplicar:** WHM → *Apache Configuration → Global Configuration* → **SSL/TLS Protocols** = `TLSv1.2 TLSv1.3`, depois *Rebuild Configuration and Restart Apache*. Em Apache puro: `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1`.
- **Como verificar:** `grep -n SSLProtocol /etc/apache2/conf/httpd.conf`; `scripts/check-tls.sh <dominio>` (TLS 1.0/1.1 com `(NONE)`, 1.2/1.3 negociando).
- **Mapeamento:** CIS 3.10 · NIST SC-8, SC-13 · NIST SP 800-52 Rev. 2 · ASVS V9.1.

## SRV-02 — TLS: ordem de cifras do servidor e sem DHE

- **Objetivo:** impedir que o cliente force uma cifra mais fraca e eliminar troca de chaves DHE (só ECDHE, com sigilo futuro).
- **Como aplicar:** [`templates/apache-tls-hardening.conf`](../templates/apache-tls-hardening.conf) no *Include Editor → Pre VirtualHost Include*. Antes, confirmar que nenhum VirtualHost redefine `SSLCipherSuite` (`grep -c SSLCipherSuite httpd.conf` = 1).
- **Como verificar:** `scripts/check-tls.sh <dominio>`: o servidor escolhe a mesma cifra para ordens opostas oferecidas pelo cliente; DHE com `handshake failure`.
- **Efeito colateral aceito:** clientes muito antigos (Windows XP/IE, Android ≤ 4.3) deixam de conectar.
- **Mapeamento:** CIS 3.10 · NIST SC-8, SC-13 · NIST SP 800-52 Rev. 2.

## SRV-03 — Controles de TLS que já vêm corretos (só conferir)

| Controle | Verificação | Esperado |
|---|---|---|
| Renegociação segura | `echo \| openssl s_client -connect <d>:443 -tls1_2 2>&1 \| grep "Secure Renegotiation"` | `IS supported` |
| Renegociação pelo cliente | `(echo R; sleep 2) \| openssl s_client -connect <d>:443 -tls1_2 2>&1 \| grep -i renegotiation` | recusada |
| 0-RTT | não habilitar `SSLEarlyData` | ausente |
| Compressão TLS | padrão do OpenSSL atual | desabilitada |

Se algum falhar, investigar antes de mudar: não é o comportamento padrão.

## SRV-04 — Certificados automáticos

- **Objetivo:** todo nome servido (`dominio`, `www`, `mail`) com certificado válido e renovação automática.
- **Como aplicar:** WHM → *Manage AutoSSL* com provedor ativo e habilitado para todos os usuários.
- **Como verificar:** logs do AutoSSL sem falhas de validação (DCV); `scripts/check-tls.sh` mostra dias restantes. Falha típica de DCV: DNS apontando para outro lugar ou `.htaccess` bloqueando `/.well-known/`.
- **Mapeamento:** NIST SC-12, SC-17 · CIS 3.10.

## SRV-05 — Apache: `mpm_event` + PHP-FPM, timeouts e limites

- **Objetivo:** evitar que conexões ociosas esgotem os workers e derrubem todos os sites (ver writeup 04 do repositório `incident-response-writeups`).
- **Como aplicar:**
  - MPM `event` com PHP-FPM para todas as contas; capacidade de referência: 16 processos × 25 threads = 400 conexões.
  - Remover `mod_ruid2` (incompatível com `event`). **Antes:** ativar o FileProtect do cPanel (docroots com grupo `nobody`, modo 750); depois, arquivos novos precisam de `644` e pastas de `755`.
  - `mod_reqtimeout` (`header=20-40,MinRate=500 body=20,MinRate=500`).
  - `Timeout` coerente com o maior `max_execution_time` em uso (referência: 120 s, nunca 300).
  - Simular a troca de pacotes (`dnf --assumeno` / `apt-get -s`) e salvar o perfil do EasyApache antes.
  - **Não reaplicar o perfil "default" do EasyApache** se ele trouxer `prefork + ruid2` de volta.
- **Como verificar:** `httpd -V | grep MPM`; `httpd -M | grep -E 'reqtimeout|ruid2'`; `grep -c AH00161 error_log` (saturação) = 0.
- **Mapeamento:** NIST SC-5 (Denial-of-Service Protection), CM-6 · CIS 4.1.

## SRV-06 — Firewall de host e detecção (CSF/lfd)

- **Objetivo:** filtrar entrada, banir abuso, **sem banir dependências legítimas**.
- **Como aplicar** (trecho de referência: [`templates/csf.conf.excerpt.example`](../templates/csf.conf.excerpt.example)):
  - `TESTING = "0"`; `CONNLIMIT` nas portas web (referência `80;150,443;150`).
  - Allowlist (`csf.allow`) para dependências operacionais, gerada a partir das listas **oficiais** dos fornecedores, com comentário de origem e revisão periódica, aplicada em **todos** os servidores.
  - Faixas oficiais de CDN/proxy reverso em `csf.ignore` (o `lfd` não bane, mas o firewall não libera).
  - Avaliar `LF_MODSEC` (ban por evento do WAF) e `LF_APACHE_403`; desligar `PT_USER*` se gerar alertas sem ação.
  - Monitorar `systemctl is-active csf` **separadamente** de `lfd`: o CSF pode ficar `failed` com o `lfd` ativo.
  - Em sistemas com `nftables.service` habilitado ao lado do CSF: revisar. A unit pode ter `ExecStop=nft flush ruleset`, que apaga o firewall inteiro; desabilitar com `disable` (sem `stop`).
- **Como verificar:** `scripts/check-server-baseline.sh` (seção Firewall); ocupação do `csf.deny` vs `DENY_IP_LIMIT`; `grep "<ip>" /var/log/lfd.log` ao investigar indisponibilidade parcial.
- **Mapeamento:** CIS 4.4, 4.5, 13.3 · NIST SC-7, SI-4.

## SRV-07 — Proteção contra força bruta em painéis (cPHulk)

- **Objetivo:** limitar tentativas de login em WHM/cPanel/webmail sem derrubar redes inteiras.
- **Como aplicar:** cPHulk ligado, com **bloqueio no firewall desligado** (um IP bloqueado perde só o login, não os sites: importante quando muitos usuários saem por um mesmo NAT); limiares por IP e por usuário; IPs administrativos fixos na whitelist.
- **Como verificar:** `whmapi1 servicestatus service=cphulkd`; falhas reais aparecendo no histórico (tentativas a partir de `127.0.0.1` são ignoradas e não servem de teste).
- **Mapeamento:** NIST AC-7 (Unsuccessful Logon Attempts).

## SRV-08 — WAF (ModSecurity + OWASP CRS)

- **Objetivo:** filtrar ataques de aplicação antes do PHP.
- **Como aplicar:** ModSecurity com conjunto de regras mantido; regras locais com IDs próprios em arquivo de usuário (com backup); exceções por regra e por caminho, nunca desligar o WAF do vhost inteiro.
- **Como verificar:** `httpd -M | grep security2`; inventário de vhosts com ModSecurity desligado (cada um é uma lacuna); `error_log` por IDs de regra que mais disparam contra tráfego legítimo.
- **Mapeamento:** CIS 13.10 (Application Layer Filtering) · NIST SC-7, SI-3 · OWASP CRS.

## SRV-09 — SSH

- **Objetivo:** acesso administrativo só com chave e com chaves rastreáveis.
- **Como aplicar:**
  - `PermitRootLogin prohibit-password` e `PasswordAuthentication no` (**testar o login por chave em uma segunda sessão antes de recarregar o `sshd`**).
  - Inventário de `authorized_keys` com dono identificado; remover chaves sem dono.
  - Chaves distintas por finalidade (automação ≠ acesso humano); uma chave de servidor aceita em vários outros vira caminho de movimento lateral.
  - Porta documentada; trocar a porta reduz ruído de log, não substitui os itens acima.
- **Como verificar:** `sshd -T | grep -E 'permitrootlogin|passwordauthentication|^port'`; `ssh-keygen -lf /root/.ssh/authorized_keys`.
- **Mapeamento:** CIS 5.4, 6.5 · NIST AC-17, IA-2, IA-5.

## SRV-10 — PHP: versões suportadas e resposta a CVE

- **Objetivo:** nenhum site ativo em versão sem correção de segurança.
- **Como aplicar:**
  - Inventário por vhost (`whmapi1 php_get_vhost_versions`), incluindo overrides por `.htaccess` em subpastas e crons com binário fixo.
  - Em pacotes com retroporte, confirmar a correção pelo **changelog citar o CVE**, não pelo número da versão.
  - Após atualizar, reiniciar PHP-FPM/Apache e conferir que nenhum processo usa binário `(deleted)`.
  - Remover versões sem uso (contando contas suspensas), com perfil do EasyApache salvo.
  - `disable_functions` e limites definidos no nível do servidor/pool, onde a conta não consiga sobrescrever.
- **Como verificar:** playbook `resposta-cve-php.md` do repositório `incident-response-writeups`; `scripts/check-server-baseline.sh` (seção PHP).
- **Mapeamento:** CIS 2.2, 7.3, 7.4 · NIST SI-2, CM-7, RA-5.

## SRV-11 — PHP: OPcache isolado por conta

- **Objetivo:** desempenho (o PHP não recompila o WordPress a cada requisição) sem vazar informação entre contas.
- **Como aplicar:** [`templates/php-opcache.ini.example`](../templates/php-opcache.ini.example): memória proporcional ao número de arquivos `.php`, `validate_permission=1`, `restrict_api=/root/`. Instalar o pacote na mesma versão do PHP já instalado.
- **Como verificar:** `php-fpm -i | grep opcache`; taxa de acerto e uso de memória do cache por script restrito ao root.
- **Mapeamento:** NIST SC-4 (Information in Shared System Resources), SC-5.

## SRV-12 — Banco de dados só em loopback

- **Objetivo:** MariaDB/MySQL não exposto na rede.
- **Como aplicar:** `bind-address = 127.0.0.1` em `/etc/my.cnf` (ou no `.d` da distribuição); senhas e contas anônimas tratadas pelo procedimento de instalação segura.
- **Como verificar:** `ss -ltnp | grep 3306` mostra só `127.0.0.1`.
- **Mapeamento:** CIS 4.1 · NIST SC-7, CM-7.

## SRV-13 — DNS do servidor e identidade

- **Objetivo:** um único serviço de DNS ativo e hostname resolvível com reverso correto.
- **Como aplicar:** um servidor DNS (ex.: PowerDNS) ativo e o outro (BIND) desabilitado; hostname em domínio próprio, com A, PTR, SPF (e DKIM) — ver [03](03-email.md).
- **Como verificar:** `systemctl is-active pdns named`; `dig +short -x <ip>`; `dig +short TXT $(hostname -f)`.
- **Mapeamento:** NIST SC-20, SC-21 · CIS 4.1.

## SRV-14 — Fuso horário e sincronização de hora

- **Objetivo:** logs correlacionáveis e crons (backup, rotinas) no horário esperado.
- **Como aplicar:** `timedatectl set-timezone <fuso-do-negócio>` **antes** de configurar crons (provedores entregam a máquina com o fuso do datacenter); NTP ativo (`chronyd` ou `systemd-timesyncd`).
- **Como verificar:** `timedatectl` (`Time zone` e `System clock synchronized: yes`).
- **Mapeamento:** CIS 8.4 · NIST AU-8.

## SRV-15 — Sistema operacional padronizado e atualizado

- **Objetivo:** paridade entre servidores (scripts de operação funcionam em todos) e patches aplicados.
- **Como aplicar:** escolher explicitamente a mesma distribuição em toda contratação nova (o template padrão do provedor pode ser outro); janela de manutenção para kernel e reboot; atualizações do painel automáticas.
- **Como verificar:** `/etc/os-release`; `needs-restarting -r` (RHEL-like) ou `/var/run/reboot-required` (Debian-like).
- **Mapeamento:** CIS 4.1, 7.3 · NIST CM-2, SI-2.

## SRV-16 — Backups

- **Objetivo:** recuperar contas inteiras após incidente sem esgotar o disco de produção.
- **Como aplicar:**
  - Backup diário local + **cópia remota** (bucket/objeto em outro provedor ou conta), com remoção do local **somente depois** de validar que 100% dos arquivos chegaram ao destino.
  - Retenção local dimensionada pelo disco do servidor (a de longo prazo fica no remoto); não copiar o padrão do template.
  - Capacidade: o backup duplica temporariamente o espaço de cada conta. Regra prática para alocar contas: `uso atual + tamanho da conta × 2`, evitando passar de ~75–80%.
  - Proteção contra execução duplicada (`flock`) e monitoramento central do resultado.
  - Janela fora do horário comercial.
  - Teste periódico de restauração de uma conta real.
- **Como verificar:** `whmapi1 backup_config_get`; log do job de envio; uso de disco no pico do backup.
- **Mapeamento:** CIS 11.2, 11.3, 11.4, 11.5 · NIST CP-9, CP-10.

## SRV-17 — Canal de alertas confiável

- **Objetivo:** alertas do servidor chegam à equipe e não prejudicam a reputação de e-mail do servidor.
- **Como aplicar:** hostname com SPF/DKIM, ou relay SMTP autenticado só para mensagens do sistema (ver [03](03-email.md)); destino do root definido em todos os lugares em que o painel o lê; desligar alertas sem ação.
- **Como verificar:** `exim -bpc` (fila), bounces congelados, respostas `5.7.x` nos logs; teste de alerta ponta a ponta.
- **Mapeamento:** NIST AU-5, SI-4 · CIS 8.11.

## SRV-18 — Nada sensível dentro dos docroots

- **Objetivo:** nenhuma cópia de backup, dump de banco, chave ou instalador acessível pela web.
- **Como aplicar:** varredura periódica por `*.sql`, `*.tar.gz`, `backup-*`, `homedir/`, `*.bak`, `installer.php*`, `*.key`, `.env` nos docroots; **mover** para área só de root com `LEIA-ME`, não apagar de imediato; checar logs de acesso aos arquivos antes de mover.
- **Como verificar:** `scripts/check-server-baseline.sh --scan-docroots`; `curl -s -o /dev/null -w '%{http_code}'` em cada achado.
- **Mapeamento:** CIS 3.3 · NIST AC-3, SC-28 · OWASP Top 10 A05 (Security Misconfiguration).
