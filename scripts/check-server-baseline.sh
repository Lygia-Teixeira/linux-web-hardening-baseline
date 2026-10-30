#!/usr/bin/env bash
# check-server-baseline.sh - auditoria SOMENTE LEITURA de um servidor Linux com
# cPanel/WHM, Apache, Exim e CSF/lfd contra a baseline deste repositorio.
#
# Nao altera nada: apenas le arquivos de configuracao, estado de servicos
# (systemctl is-active/is-enabled), sockets em escuta e saidas de "-V"/"-T".
# Itens ausentes (ex.: servidor sem cPanel) sao reportados como SKIP.
#
# Uso: sudo check-server-baseline.sh [--scan-docroots]
#   --scan-docroots  procura arquivos de backup/dump expostos em /home/*/public_html
#                    (pode demorar em servidores com muitos sites)
#
# Codigo de saida = numero de FAIL (max 125).
# Licenca: MIT. (c) 2026 Lygia Teixeira

set -euo pipefail

SCAN_DOCROOTS=0
for a in "$@"; do
  case "$a" in
    --scan-docroots) SCAN_DOCROOTS=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "opcao desconhecida: $a" >&2; exit 2 ;;
  esac
done

FAILS=0; WARNS=0
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '[FAIL] %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '[INFO] %s\n' "$*"; }
skip() { printf '[SKIP] %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Le "CHAVE = valor" de arquivos estilo csf.conf (aspas removidas)
conf_get() {
  local file="$1" key="$2"
  [ -r "$file" ] || return 0
  sed -n -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*\"?([^\"]*)\"?.*$/\1/p" "$file" | tail -n1
}

svc_active() { have systemctl && [ "$(systemctl is-active "$1" 2>/dev/null || true)" = "active" ]; }
svc_enabled() { have systemctl && [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = "enabled" ]; }

[ "$(id -u)" -eq 0 ] || warn "Rodando sem root: varios arquivos nao serao legiveis"

# ---------------------------------------------------------------------------
section "Sistema operacional, hora e atualizacoes"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  info "SO: $(. /etc/os-release; printf '%s' "${PRETTY_NAME:-desconhecido}")"
fi
info "Kernel: $(uname -r)"

if have timedatectl; then
  TZ_NOW="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  NTP_SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  info "Timezone: ${TZ_NOW:-desconhecido} (confirmar que e o fuso do negocio, nao o do datacenter)"
  if [ "$NTP_SYNC" = "yes" ]; then pass "Relogio sincronizado via NTP"; else fail "Relogio NAO sincronizado via NTP"; fi
else
  skip "timedatectl indisponivel"
fi

if [ -f /var/run/reboot-required ]; then
  warn "Reboot pendente (/var/run/reboot-required)"
elif have needs-restarting; then
  if ! needs-restarting -r >/dev/null 2>&1; then warn "Reboot pendente (needs-restarting -r)"; fi
fi

# ---------------------------------------------------------------------------
section "Contas e acesso privilegiado"
if [ -r /etc/passwd ]; then
  UID0="$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')"
  if [ "$UID0" = "root " ]; then pass "Somente root com UID 0"; else fail "Contas com UID 0: $UID0"; fi
else
  skip "/etc/passwd nao legivel"
fi

if [ -r /etc/sudoers ]; then
  NOPW="$(grep -rhs NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -vcE 'wp-toolkit|cloud-init' || true)"
  if [ "${NOPW:-0}" -eq 0 ]; then pass "Nenhuma regra NOPASSWD fora do esperado"; else warn "$NOPW regra(s) NOPASSWD em sudoers: revisar"; fi
fi

# ---------------------------------------------------------------------------
section "SSH"
if have sshd; then
  SSHD_T="$(sshd -T 2>/dev/null || true)"
  if [ -n "$SSHD_T" ]; then
    PRL="$(awk '$1=="permitrootlogin"{print $2}' <<<"$SSHD_T")"
    PWA="$(awk '$1=="passwordauthentication"{print $2}' <<<"$SSHD_T")"
    PORT="$(awk '$1=="port"{print $2}' <<<"$SSHD_T" | tr '\n' ' ')"
    info "Porta(s) SSH: $PORT"
    case "$PRL" in
      no|prohibit-password|without-password) pass "PermitRootLogin $PRL" ;;
      *) fail "PermitRootLogin $PRL (root com senha pela rede)" ;;
    esac
    if [ "$PWA" = "no" ]; then pass "PasswordAuthentication no"; else warn "PasswordAuthentication $PWA"; fi
  else
    skip "sshd -T sem saida (rodar como root)"
  fi
else
  skip "sshd nao encontrado"
fi
if [ -r /root/.ssh/authorized_keys ]; then
  info "Chaves autorizadas do root: $(grep -cvE '^[[:space:]]*(#|$)' /root/.ssh/authorized_keys || true) (revisar dono de cada uma)"
fi

# ---------------------------------------------------------------------------
section "Firewall (CSF/lfd) e protecao contra forca bruta"
CSF=/etc/csf/csf.conf
if [ -r "$CSF" ]; then
  if svc_active csf; then pass "csf ativo"; else fail "csf NAO ativo (pode falhar silenciosamente com lfd ativo)"; fi
  if svc_active lfd; then pass "lfd ativo"; else fail "lfd NAO ativo"; fi
  TESTING="$(conf_get "$CSF" TESTING)"
  if [ "$TESTING" = "0" ]; then pass "CSF fora do modo TESTING"; else fail "CSF em modo TESTING=$TESTING"; fi

  CONNLIMIT="$(conf_get "$CSF" CONNLIMIT)"
  if [ -n "$CONNLIMIT" ]; then pass "CONNLIMIT definido ($CONNLIMIT)"; else warn "CONNLIMIT vazio (sem limite de conexoes simultaneas por IP)"; fi

  LIMIT="$(conf_get "$CSF" DENY_IP_LIMIT)"
  if [ -r /etc/csf/csf.deny ] && [ -n "$LIMIT" ] && [ "$LIMIT" -gt 0 ] 2>/dev/null; then
    USED="$(grep -cvE '^[[:space:]]*(#|$)' /etc/csf/csf.deny || true)"
    PCT=$(( USED * 100 / LIMIT ))
    if [ "$PCT" -ge 90 ]; then warn "csf.deny com $USED/$LIMIT entradas: possivel falso positivo em massa (CDN, ferramenta de gestao)"
    else pass "csf.deny com $USED/$LIMIT entradas"; fi
  fi

  for k in PT_USERMEM PT_USERRSS PT_USERTIME; do
    v="$(conf_get "$CSF" "$k")"
    if [ -n "$v" ] && [ "$v" != "0" ]; then
      warn "$k=$v: alertas por processo podem gerar milhares de e-mails/dia (avaliar volume)"
    fi
  done
  info "LF_MODSEC=$(conf_get "$CSF" LF_MODSEC) LF_APACHE_403=$(conf_get "$CSF" LF_APACHE_403) LF_PERMBLOCK=$(conf_get "$CSF" LF_PERMBLOCK)"
  if [ -r /etc/csf/csf.allow ]; then
    info "csf.allow: $(grep -cvE '^[[:space:]]*(#|$)' /etc/csf/csf.allow || true) entradas (dependencias legitimas estao aqui?)"
  fi
else
  skip "CSF nao encontrado: conferir outro firewall de host"
fi

if have systemctl && systemctl cat nftables.service >/dev/null 2>&1; then
  if svc_enabled nftables && [ -r "$CSF" ]; then
    warn "nftables.service habilitado junto com CSF: revisar (ExecStop pode limpar todo o ruleset)"
  fi
fi

if [ -d /usr/local/cpanel ]; then
  if have whmapi1; then
    CPH="$(whmapi1 servicestatus service=cphulkd 2>/dev/null | awk '/running:/{print $2; exit}' || true)"
    if [ "$CPH" = "1" ]; then pass "cPHulk em execucao"; else warn "cPHulk nao esta em execucao"; fi
  fi
fi

# ---------------------------------------------------------------------------
section "Apache"
APACHECTL=""
for c in httpd apachectl apache2ctl; do have "$c" && { APACHECTL="$c"; break; }; done
if [ -n "$APACHECTL" ]; then
  V="$("$APACHECTL" -V 2>/dev/null || true)"
  MPM="$(awk -F': *' '/Server MPM/{print $2}' <<<"$V" | tr -d ' ')"
  case "${MPM,,}" in
    event) pass "MPM event" ;;
    worker) pass "MPM worker" ;;
    prefork) warn "MPM prefork (cada conexao ocupa um processo; avaliar event + PHP-FPM)" ;;
    *) info "MPM: ${MPM:-desconhecido}" ;;
  esac
  MODS="$("$APACHECTL" -M 2>/dev/null || true)"
  if grep -q reqtimeout_module <<<"$MODS"; then pass "mod_reqtimeout carregado"; else warn "mod_reqtimeout ausente (conexoes lentas seguram workers)"; fi
  if grep -q headers_module <<<"$MODS"; then pass "mod_headers carregado"; else fail "mod_headers ausente (cabecalhos do .htaccess nao funcionam)"; fi
  if grep -q security2_module <<<"$MODS"; then pass "ModSecurity carregado"; else warn "ModSecurity nao carregado"; fi
  if grep -q ruid2_module <<<"$MODS"; then info "mod_ruid2 presente (incompativel com MPM event)"; fi
else
  skip "Apache nao encontrado"
fi

HTTPD_CONF=""
for f in /etc/apache2/conf/httpd.conf /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf; do
  [ -r "$f" ] && { HTTPD_CONF="$f"; break; }
done
if [ -n "$HTTPD_CONF" ]; then
  INC_DIR="$(dirname "$HTTPD_CONF")/../conf.d"
  ALL_CONF="$(cat "$HTTPD_CONF" "$INC_DIR"/*.conf "$INC_DIR"/includes/*.conf 2>/dev/null || true)"
  PROTO="$(grep -iE '^[[:space:]]*SSLProtocol' <<<"$ALL_CONF" | tail -n1 | sed 's/^[[:space:]]*//' || true)"
  if [ -n "$PROTO" ]; then
    if grep -qiE -e '-TLSv1([^.]|$)' <<<"$PROTO" && grep -qiE -e '-TLSv1\.1' <<<"$PROTO"; then pass "$PROTO"
    elif grep -qiE 'SSLProtocol[[:space:]]+(\+?TLSv1\.[23][[:space:]]*)+$' <<<"$PROTO"; then pass "$PROTO"
    else fail "TLS antigo possivelmente habilitado: $PROTO"; fi
  else
    warn "SSLProtocol nao encontrado nos arquivos lidos"
  fi
  if grep -qiE '^[[:space:]]*SSLHonorCipherOrder[[:space:]]+on' <<<"$ALL_CONF"; then pass "SSLHonorCipherOrder On"; else fail "SSLHonorCipherOrder nao esta On"; fi
  SUITE="$(grep -iE '^[[:space:]]*SSLCipherSuite' <<<"$ALL_CONF" | tail -n1 || true)"
  if [ -n "$SUITE" ]; then
    if grep -qE '(^|[: ])(EDH|DHE)-' <<<"$SUITE"; then fail "SSLCipherSuite inclui DHE"; else pass "SSLCipherSuite sem DHE explicito (confirmar com check-tls.sh)"; fi
  fi
  TMO="$(grep -iE '^[[:space:]]*Timeout[[:space:]]+[0-9]+' "$HTTPD_CONF" | awk '{print $2}' | tail -n1 || true)"
  if [ -n "$TMO" ]; then
    if [ "$TMO" -gt 120 ]; then warn "Timeout $TMO s (alto; conexoes paradas seguram workers)"; else pass "Timeout $TMO s"; fi
  fi
  if grep -qiE '^[[:space:]]*SSLEarlyData[[:space:]]+on' <<<"$ALL_CONF"; then fail "SSLEarlyData (0-RTT) habilitado"; fi
fi

# ---------------------------------------------------------------------------
section "PHP"
if ls -d /opt/cpanel/ea-php*/ >/dev/null 2>&1; then
  for d in /opt/cpanel/ea-php*/; do
    v="$(basename "$d")"; n="${v#ea-php}"
    bin="$d/root/usr/bin/php"
    [ -x "$bin" ] || { info "$v: pasta sem binario (sobra de versao removida?)"; continue; }
    if [ "$n" -lt 81 ] 2>/dev/null; then warn "$v instalado (fora de suporte do upstream)"; else info "$v instalado"; fi
    if ls "$d"/root/etc/php.d/*opcache*.ini >/dev/null 2>&1; then
      pass "$v com OPcache"
    else
      warn "$v sem OPcache (PHP recompila os scripts a cada requisicao)"
    fi
  done
else
  have php && info "PHP: $(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
fi
for p in $(pgrep -f 'php-fpm|lsphp|httpd|apache2' 2>/dev/null || true); do
  if readlink "/proc/$p/exe" 2>/dev/null | grep -q deleted; then
    warn "PID $p usa binario substituido (reiniciar servico apos atualizacao)"; break
  fi
done

# ---------------------------------------------------------------------------
section "Banco de dados"
if have ss; then
  DBL="$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E ':3306$' || true)"
  if [ -z "$DBL" ]; then info "Nada escutando em 3306"
  elif grep -qvE '^(127\.0\.0\.1|\[::1\]):3306$' <<<"$DBL"; then fail "MySQL/MariaDB escutando fora do loopback: $(tr '\n' ' ' <<<"$DBL")"
  else pass "MySQL/MariaDB apenas em loopback"; fi
fi

# ---------------------------------------------------------------------------
section "E-mail (Exim)"
LOC=/etc/exim.conf.localopts
if [ -r "$LOC" ]; then
  OO="$(conf_get "$LOC" openssl_options)"
  if grep -q '+no_tlsv1_1' <<<"$OO" && grep -q '+cipher_server_preference' <<<"$OO"; then
    pass "Exim openssl_options: $OO"
  else
    fail "Exim openssl_options sem +no_tlsv1_1/+cipher_server_preference (${OO:-vazio})"
  fi
  TRC="$(conf_get "$LOC" tls_require_ciphers)"
  if [ -n "$TRC" ] && ! grep -qE '(^|:)(EDH|DHE)-' <<<"$TRC"; then pass "Exim tls_require_ciphers sem DHE"; else warn "Exim tls_require_ciphers vazio ou com DHE"; fi
  if [ "$(conf_get "$LOC" acl_dkim_disable)" = "1" ]; then warn "acl_dkim_disable=1 (mensagens do sistema sem DKIM)"; fi
fi
if have exim; then
  Q="$(exim -bpc 2>/dev/null || echo '?')"
  if [ "$Q" != "?" ] && [ "$Q" -gt 1000 ]; then warn "Fila do Exim com $Q mensagens (alertas rejeitados? bounces?)"; else info "Fila do Exim: $Q"; fi
fi
if have dig; then
  HN="$(hostname -f 2>/dev/null || hostname)"
  if dig +short TXT "$HN" 2>/dev/null | grep -q 'v=spf1'; then pass "SPF publicado para o hostname $HN"
  else warn "Sem SPF para o hostname $HN (alertas do servidor podem ser rejeitados)"; fi
fi

# ---------------------------------------------------------------------------
section "Backups"
if [ -d /usr/local/cpanel ] && have whmapi1; then
  BC="$(whmapi1 backup_config_get 2>/dev/null || true)"
  EN="$(awk '/^[[:space:]]+backupenable:/{print $2; exit}' <<<"$BC")"
  RET="$(awk '/^[[:space:]]+backup_daily_retention:/{print $2; exit}' <<<"$BC")"
  LOCAL="$(awk '/^[[:space:]]+keeplocal:/{print $2; exit}' <<<"$BC")"
  case "$EN" in 1|yes) pass "Backup do cPanel habilitado" ;; *) fail "Backup do cPanel desabilitado (backupenable=${EN:-?})" ;; esac
  info "Retencao diaria local: ${RET:-?}; keeplocal: ${LOCAL:-?} (dimensionar pelo disco; copia remota e obrigatoria)"
fi
for m in / /home /backup; do
  [ -d "$m" ] || continue
  USEP="$(df -P "$m" 2>/dev/null | awk 'NR==2{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+%$/) {sub("%","",$i); print $i; exit}}' || true)"
  [ -n "$USEP" ] || continue
  if [ "$USEP" -ge 85 ]; then warn "Uso de disco em $m: ${USEP}% (o backup diario duplica temporariamente o espaco das contas)"
  else info "Uso de disco em $m: ${USEP}%"; fi
done

# ---------------------------------------------------------------------------
section "Arquivos expostos nos docroots"
if [ "$SCAN_DOCROOTS" -eq 1 ]; then
  if ls -d /home/*/public_html >/dev/null 2>&1; then
    FOUND="$(find /home/*/public_html -maxdepth 4 -type f \( \
        -name '*.sql' -o -name '*.sql.gz' -o -name 'backup-*.tar*' -o -name '*.tar.gz' \
        -o -name '*.bak' -o -name 'installer.php*' -o -name '*.key' -o -name '.env' \) \
        -size +0 2>/dev/null | head -n 50 || true)"
    if [ -z "$FOUND" ]; then pass "Nenhum dump/backup/chave encontrado ate profundidade 4"
    else
      warn "Arquivos sensiveis em docroots (confirmar se respondem 200 pela web):"
      printf '%s\n' "$FOUND" | sed 's/^/        /'
    fi
  else
    skip "Sem /home/*/public_html"
  fi
else
  info "Use --scan-docroots para procurar dumps, backups e chaves dentro dos docroots"
fi

printf '\n== Resultado: %d FAIL, %d WARN\n' "$FAILS" "$WARNS"
[ "$FAILS" -gt 125 ] && FAILS=125
exit "$FAILS"
