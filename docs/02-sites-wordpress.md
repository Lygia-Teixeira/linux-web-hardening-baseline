# 02 — Controles por site (WordPress em conta cPanel)

Controles aplicados **em cada conta/site**. Antes de qualquer item:

```bash
U=<usuario>
cp -p /home/$U/public_html/.htaccess /home/$U/htaccess.bkp-$(date +%Y%m%d)-<motivo>
```

Antes de testar, confirmar para onde o domínio aponta **de fora** (`dig +short A <dominio> @1.1.1.1`). Se apontar para uma CDN/proxy reverso, o TLS e a compressão vistos pelo visitante são os da CDN; os cabeçalhos do `.htaccess` passam pelo proxy normalmente.

Para aplicação em lote, o script deve: fazer backup de cada `.htaccess`, medir código HTTP de home e login antes/depois, e **reverter sozinho** se o site passar a dar 5xx ou não responder. Use um tempo-limite generoso: sites com login lento geram reversões falso-positivas.

---

## WEB-01 — HTTPS com redirecionamento permanente

- **Objetivo:** todo acesso em HTTP vira HTTPS.
- **Como aplicar:** cPanel → *Domínios* → **Force HTTPS Redirect** (botão desabilitado = certificado ainda não emitido).
- **Como verificar:** `curl -sI http://<dominio>/ | grep -iE '^(HTTP|location)'` → `301` para `https://`. Ou `scripts/check-headers.sh <dominio>`.
- **Mapeamento:** CIS 3.10 · NIST SC-8 · ASVS V9.1.1.

## WEB-02 — HSTS

- **Objetivo:** o navegador passa a usar sempre HTTPS, evitando downgrade.
- **Como aplicar:** [`templates/htaccess-security-headers.conf`](../templates/htaccess-security-headers.conf) (`max-age=31536000`, enviado só em HTTPS). **Sem `includeSubDomains`** até inventariar subdomínios: um subdomínio sem certificado ficaria inacessível.
- **Como verificar:** `scripts/check-headers.sh`.
- **Mapeamento:** ASVS V14.4.5 · OWASP Secure Headers Project · NIST SC-8.

## WEB-03 — Cabeçalhos anti-clickjacking, anti-sniffing e de referrer

| Cabeçalho | Valor | Motivo |
|---|---|---|
| `X-Frame-Options` | `SAMEORIGIN` | Bloqueia o site em iframe de terceiros; editor e customizer do WordPress continuam funcionando |
| `X-Content-Type-Options` | `nosniff` | Navegador não "adivinha" o tipo do arquivo |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Não vaza caminho e parâmetros da URL para outros sites |

- **Como aplicar:** mesmo bloco de WEB-02, **no topo** do `.htaccess`, antes dos marcadores `# BEGIN` de plugins (plugins de segurança e cache regravam o arquivo e podem mover ou apagar o que estiver dentro dos blocos deles).
- **Como verificar:** `scripts/check-headers.sh`; home, busca e `wp-login.php` com o mesmo código de antes; console do navegador sem erros novos.
- **Mapeamento:** ASVS V14.4.4, V14.4.6, V14.4.7 · OWASP Secure Headers Project.

## WEB-04 — Content-Security-Policy em duas fases

- **Objetivo:** restringir origens de scripts, estilos, frames e formulários, reduzindo o impacto de XSS e de injeções como a do writeup 01 (`import()` para domínio externo).
- **Como aplicar:**
  1. **Fase 1:** `Content-Security-Policy-Report-Only` (só observa). Política inicial ampla, compatível com WordPress (`'unsafe-inline'`, `https:`).
  2. Navegar pelas páginas principais com o console aberto e listar as origens legítimas (vídeos, mapas, fontes, widgets, formulários).
  3. **Fase 2:** trocar para `Content-Security-Policy`, site a site, testando páginas, mídia, formulários e o painel.
  4. Evolução: restringir `script-src` a origens explícitas em vez de `https:`.
- **Como verificar:** `scripts/check-headers.sh` (Report-Only gera WARN; ferramentas externas de avaliação costumam reprovar CSP só em Report-Only).
- **Mapeamento:** ASVS V14.4.3 · OWASP Top 10 A03 (Injection).

## WEB-05 — Compressão HTTP desligada no HTML

- **Objetivo:** mitigar BREACH (ataque que explora compressão de respostas HTTPS com segredos refletidos).
- **Por que não é automático:** mesmo com o Apache sem compressão, contas com `zlib.output_compression = On` no PHP comprimem o HTML.
- **Como aplicar:** cPanel → *MultiPHP INI Editor* → `zlib.output_compression` = **Disabled**. O valor pode estar em até três lugares da conta (`php.ini`, `.user.ini` e bloco gerado pelo painel no `.htaccess`); em lote, alterar os três com backup.
- **Como verificar:** `curl -s -o /dev/null -D - -H 'Accept-Encoding: gzip' "https://<dominio>/?t=1" | grep -i content-encoding` sem saída. O `?t=` evita a cópia em cache de página, que pode continuar comprimida por alguns minutos.
- **Custo:** só o HTML trafega sem compressão (alguns KB a mais por página).
- **Mapeamento:** NIST SC-8 · ASVS V9.

## WEB-06 — Bloqueio de varreduras e robôs no Apache

- **Objetivo:** responder a caminhos de varredura inexistentes (`/.env`, `/.git`, `/actuator`, `/graphql`…) e a crawlers de IA sem carregar o WordPress.
- **Como aplicar:** preferencialmente no include global ([`templates/apache-scan-block.conf`](../templates/apache-scan-block.conf)); por site, o mesmo bloco no topo do `.htaccess`. Bloquear **só se o arquivo não existir**, com `ErrorDocument` em texto puro. Usar **410** em vez de 403 se o `lfd` bane por excesso de 403.
- **Como verificar:** nenhum site muda de código HTTP; caminhos de varredura com 403/410 em milissegundos; buscadores e geradores de prévia com 200; arquivos reais com as mesmas extensões continuam com 200.
- **Mapeamento:** CIS 13.10 · NIST SC-5, SC-7.

## WEB-07 — Arquivos que não devem estar publicados

- **Objetivo:** nenhum `.bak`, `installer.php`, dump `.sql`, backup de conta, `.user.ini` ou chave acessível pela web.
- **Como aplicar:** mover para área fora do docroot (não apagar de imediato); para arquivos que precisam ficar no lugar, bloquear com `<FilesMatch>` + `Require all denied`. Plugins de migração/clonagem costumam deixar `installer.php.bak` e pastas de backup; revisar também o site-modelo usado para clonar outros.
- **Como verificar:** `curl -s -o /dev/null -w '%{http_code}' https://<dominio>/<arquivo>` → 403/404; `scripts/check-server-baseline.sh --scan-docroots`.
- **Mapeamento:** OWASP Top 10 A05 · CIS 3.3 · NIST AC-3.

## WEB-08 — Inventário e atualização de plugins

- **Objetivo:** nenhum plugin com vulnerabilidade pública conhecida ativo.
- **Como aplicar:**
  - Inventário por versão em toda a frota, **incluindo cópias fora do docroot** (backups extraídos, `.trash`, contas suspensas): `find /home -path '*/wp-content/plugins/*/<arquivo-principal>.php'`.
  - Atualização ou substituição; plugins abandonados removidos.
  - Quando houver CVE ativa: desativar em massa (com backup de `active_plugins`) e renomear a pasta nas cópias inativas.
- **Como verificar:** `wp plugin list --fields=name,status,version,update` por conta; `wp plugin verify-checksums --all`.
- **Mapeamento:** CIS 2.2, 7.4 · NIST SI-2, RA-5 · OWASP Top 10 A06 (Vulnerable and Outdated Components).

## WEB-09 — WP-Cron executado pelo sistema, com o PHP certo

- **Objetivo:** tarefas agendadas do WordPress (inclusive renovação de chaves de agentes de gestão e de segurança) rodando de forma confiável.
- **Como aplicar:** `define('DISABLE_WP_CRON', true);` + cron do sistema por conta, chamando o binário **CLI** da versão de PHP configurada para aquela conta (`/opt/cpanel/ea-phpXX/root/usr/bin/php`), não um binário fixo nem o `cgi-fcgi`. Em scripts de cron do root, `PATH` explícito.
- **Como verificar:** `wp cron event run --due-now` com o PHP da conta, antes de ativar; `wp cron event list` sem eventos muito atrasados.
- **Mapeamento:** NIST CM-6.

## WEB-10 — Permissões de arquivos

- **Objetivo:** Apache lê o que precisa servir; nada gravável por outros.
- **Como aplicar:** arquivos `644`, pastas `755`, `wp-config.php` `600`/`640` (lido pelo PHP-FPM, que roda como o dono da conta); nunca `777`. Com o Apache rodando como `nobody` (sem `mod_ruid2`), arquivos `600` ou pastas `700` dentro do docroot geram 403.
- **Como verificar:** `find /home/<u>/public_html -perm -o+w`; `find ... -type d -perm 777`.
- **Mapeamento:** CIS 3.3 · NIST AC-3, AC-6.

## WEB-11 — Higiene de recuperação de incidentes

- Reinstalar o WordPress limpa o docroot, **não a conta**: sempre varrer a home inteira por `.php` fora do `public_html` e `.htaccess` com modo `444`.
- Código malicioso pode estar só no banco (`wp_options`, `wp_postmeta`) e só executar no navegador.
- Ver o playbook `contencao-wordpress-comprometido.md` no repositório `incident-response-writeups`.
