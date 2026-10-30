# Linux Web Hardening Baseline

Baseline de hardening para **servidores Linux de hospedagem compartilhada (cPanel/WHM, Apache, PHP-FPM, Exim, CSF/lfd)** e para os **sites WordPress** hospedados neles. Cada controle traz **objetivo, como aplicar, como verificar e mapeamento** para CIS Controls v8, NIST SP 800-53 Rev. 5 e OWASP (ASVS 4.0.3, Secure Headers, Top 10) quando faz sentido.

A baseline nasceu da aplicação real em uma frota de servidores com centenas de sites, sob avaliação externa de controles de segurança web, e-mail e DNS. Os valores adotados foram testados em produção, com backup, verificação de cada site antes/depois e rollback. Todo o conteúdo foi anonimizado.

## Estrutura

```
docs/
  01-servidor-linux-cpanel.md   controles de servidor (TLS, Apache/MPM, firewall, SSH, PHP, DB, hora, backups, alertas)
  02-sites-wordpress.md         controles por site (HTTPS, HSTS, cabeçalhos, CSP, compressão, varreduras, plugins, permissões)
  03-email.md                   TLS no SMTP, SPF, DKIM, DMARC e canal de alertas do servidor
  04-decisoes-e-excecoes.md     o que não foi adotado e por quê (DNSSEC, IPv6, OCSP, HSTS preload, CSP Report-Only…)
scripts/
  check-headers.sh              redirecionamento HTTPS, cabeçalhos de segurança e compressão de um site (de fora)
  check-tls.sh                  versões de TLS, ordem de cifras, DHE e certificado (HTTPS ou SMTP STARTTLS)
  check-server-baseline.sh      auditoria somente leitura do servidor contra a baseline
templates/
  htaccess-security-headers.conf
  apache-tls-hardening.conf
  apache-scan-block.conf
  exim-tls.localopts.example
  csf.conf.excerpt.example
  php-opcache.ini.example
  dns-email-records.example.txt
```

## Resumo dos controles

| ID | Controle | Escopo | Verificação | Mapeamento principal |
|---|---|---|---|---|
| SRV-01/02 | TLS 1.2/1.3, ordem do servidor, sem DHE | Servidor | `check-tls.sh` | CIS 3.10 · NIST SC-8/SC-13 · SP 800-52r2 |
| SRV-04 | Certificados automáticos | Servidor | `check-tls.sh` | NIST SC-17 |
| SRV-05 | `mpm_event` + PHP-FPM, `mod_reqtimeout`, timeouts | Servidor | `check-server-baseline.sh` | NIST SC-5 |
| SRV-06 | CSF/lfd com allowlist de dependências e CDN | Servidor | `check-server-baseline.sh` | CIS 4.4/4.5 · NIST SC-7 |
| SRV-07 | Força bruta em painéis (cPHulk) | Servidor | `check-server-baseline.sh` | NIST AC-7 |
| SRV-08 | WAF (ModSecurity + CRS) | Servidor | `check-server-baseline.sh` | CIS 13.10 |
| SRV-09 | SSH só com chave | Servidor | `check-server-baseline.sh` | CIS 5.4/6.5 · NIST AC-17 |
| SRV-10/11 | PHP suportado, resposta a CVE, OPcache isolado | Servidor | `check-server-baseline.sh` | CIS 7.3/7.4 · NIST SI-2 |
| SRV-12 | Banco só em loopback | Servidor | `check-server-baseline.sh` | NIST SC-7 |
| SRV-14 | Fuso horário e NTP | Servidor | `check-server-baseline.sh` | CIS 8.4 · NIST AU-8 |
| SRV-16 | Backups local + remoto, retenção por disco | Servidor | `check-server-baseline.sh` | CIS 11.2–11.5 · NIST CP-9 |
| SRV-17 | Canal de alertas confiável | Servidor | `check-server-baseline.sh` | NIST AU-5/SI-4 |
| SRV-18 / WEB-07 | Nada sensível nos docroots | Servidor/site | `--scan-docroots` | OWASP A05 |
| WEB-01/02 | HTTPS 301 + HSTS | Site | `check-headers.sh` | ASVS V9.1.1, V14.4.5 |
| WEB-03 | XFO, nosniff, Referrer-Policy | Site | `check-headers.sh` | ASVS V14.4.4/6/7 |
| WEB-04 | CSP em duas fases | Site | `check-headers.sh` | ASVS V14.4.3 |
| WEB-05 | Compressão HTTP desligada no HTML (BREACH) | Site | `check-headers.sh` | NIST SC-8 |
| WEB-06 | Bloqueio de varreduras/robôs sem PHP | Servidor/site | manual (`curl`) | CIS 13.10 |
| WEB-08 | Inventário e atualização de plugins | Site | `wp plugin list` | OWASP A06 · NIST SI-2 |
| MAIL-01 | TLS no SMTP igual ao HTTPS | Servidor | `check-tls.sh --smtp` | NIST SC-8 |
| MAIL-02/03/04 | SPF, DKIM, DMARC `p=quarantine` | Domínio | `dig` | CIS 9.5 · SP 800-177r1 |

## Uso rápido dos scripts

Todos são **somente leitura**, escritos com `set -euo pipefail`, sem credenciais e sem dependências além de `bash`, `curl`, `openssl` e utilitários padrão.

```bash
# de qualquer máquina
./scripts/check-headers.sh https://www.example.com/
./scripts/check-tls.sh www.example.com
./scripts/check-tls.sh --smtp mail.example.com 25

# no servidor (como root, para ler as configurações)
sudo ./scripts/check-server-baseline.sh
sudo ./scripts/check-server-baseline.sh --scan-docroots
```

Saída: uma linha `PASS`/`WARN`/`FAIL`/`INFO`/`SKIP` por item. O código de saída é o número de `FAIL`, o que permite usar os scripts em CI ou em verificações agendadas.

## Princípios

1. **Backup antes, verificação depois, rollback pronto.** Toda mudança tem um "como desfazer".
2. **Medir cada site antes e depois** (código HTTP de home, busca e login). Aplicação em lote reverte sozinha quando um site passa a falhar.
3. **Testar de fora.** Dentro do servidor, o DNS local responde pela zona do próprio painel e pode mostrar um resultado diferente do que o público vê.
4. **Controles defensivos também causam incidentes.** WAF e IPS de host precisam de allowlist de dependências e monitoramento de falso positivo.
5. **Registrar decisões e exceções** com motivo e gatilho para revisitar ([docs/04](docs/04-decisoes-e-excecoes.md)).

## Repositório relacionado

- `incident-response-writeups`: incidentes reais que motivaram vários destes controles (ClickFix via plugin, webshells persistentes, falso positivo de WAF, saturação do Apache, reputação de e-mail).

## Aviso

Material de referência. Revise cada valor para o seu ambiente antes de aplicar; teste em um servidor ou site de homologação.

## Licença

[MIT](LICENSE). © 2026 Lygia Teixeira.
