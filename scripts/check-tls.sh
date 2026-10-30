#!/usr/bin/env bash
# check-tls.sh - verifica versoes de TLS, ordem de cifras do servidor, recusa de DHE
# e validade do certificado, em HTTPS ou em SMTP com STARTTLS. Somente leitura.
#
# Uso: check-tls.sh [--smtp] <host> [porta]
#   ex.: check-tls.sh www.example.com
#        check-tls.sh --smtp mail.example.com 25
#
# Codigo de saida = numero de FAIL (max 125).
# Licenca: MIT. (c) 2026 Lygia Teixeira

set -euo pipefail

MODE=https
if [ "${1:-}" = "--smtp" ]; then MODE=smtp; shift; fi
[ $# -ge 1 ] || { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

HOST="$1"
if [ "$MODE" = smtp ]; then PORT="${2:-25}"; else PORT="${2:-443}"; fi
TO=10

command -v openssl >/dev/null 2>&1 || { echo "openssl nao encontrado" >&2; exit 2; }

FAILS=0
WARNS=0
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '[FAIL] %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '[INFO] %s\n' "$*"; }

probe() {
  # imprime a saida do handshake; argumentos extras vao para o openssl s_client
  local extra=()
  [ "$MODE" = smtp ] && extra=(-starttls smtp)
  local input="Q"
  [ "$MODE" = smtp ] && input="QUIT"
  printf '%s\n' "$input" | timeout "$TO" openssl s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" ${extra[@]+"${extra[@]}"} "$@" 2>&1 || true
}

cipher_of() {
  # extrai o nome da cifra negociada ("(NONE)" ou vazio quando falha)
  printf '%s\n' "$1" | grep -m1 -oE 'Cipher is [^ ]+' | awk '{print $3}' || true
}

supports() {
  # 0 se o openssl local suporta a opcao (ex.: -tls1_3)
  local h
  h="$(openssl s_client -help 2>&1 || true)"
  grep -q -- "$1" <<<"$h"
}

echo "== Alvo: ${HOST}:${PORT} (${MODE})"

# 1. Versoes antigas devem ser recusadas
for v in tls1 tls1_1; do
  if ! supports "-$v"; then info "openssl local sem -$v; teste pulado"; continue; fi
  c="$(cipher_of "$(probe "-$v")")"
  if [ -z "$c" ] || [ "$c" = "(NONE)" ]; then
    pass "${v/_/.} recusado"
  else
    fail "${v/_/.} aceito (cifra $c)"
  fi
done

# 2. TLS 1.2 e 1.3 devem negociar
c12="$(cipher_of "$(probe -tls1_2)")"
if [ -n "$c12" ] && [ "$c12" != "(NONE)" ]; then pass "TLS 1.2 negociado ($c12)"; else fail "TLS 1.2 nao negocia"; fi

if supports "-tls1_3"; then
  c13="$(cipher_of "$(probe -tls1_3)")"
  if [ -n "$c13" ] && [ "$c13" != "(NONE)" ]; then pass "TLS 1.3 negociado ($c13)"; else warn "TLS 1.3 nao negocia"; fi
else
  info "openssl local sem -tls1_3; teste pulado"
fi

# 3. Ordem de cifras: oferecer as mesmas cifras em duas ordens opostas.
#    Se o servidor escolhe a mesma cifra nas duas, ele impoe a propria ordem.
L1='ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
L2='ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
O1="$(cipher_of "$(probe -tls1_2 -cipher "$L1")")"
O2="$(cipher_of "$(probe -tls1_2 -cipher "$L2")")"
if [ -z "$O1" ] || [ -z "$O2" ] || [ "$O1" = "(NONE)" ] || [ "$O2" = "(NONE)" ]; then
  warn "Nao foi possivel avaliar a ordem de cifras (${O1:-sem resposta} / ${O2:-sem resposta})"
elif [ "$O1" = "$O2" ]; then
  pass "Servidor impoe a propria ordem de cifras (escolhe $O1 nas duas ordens)"
  case "$O1" in *AES128*) info "Preferencia do servidor e AES128; a baseline deste repositorio prioriza AES256" ;; esac
else
  fail "Servidor segue a preferencia do cliente ($O1 / $O2)"
fi

# 4. DHE deve ser recusado (apenas ECDHE)
DHE="$(cipher_of "$(probe -tls1_2 -cipher 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256')")"
if [ -z "$DHE" ] || [ "$DHE" = "(NONE)" ]; then
  pass "DHE recusado"
else
  fail "DHE aceito ($DHE)"
fi

# 5. Certificado
CERT="$(probe | openssl x509 -noout -enddate -subject -ext subjectAltName 2>/dev/null || true)"
if [ -z "$CERT" ]; then
  fail "Nao foi possivel ler o certificado"
else
  END="$(printf '%s\n' "$CERT" | sed -n 's/^notAfter=//p')"
  if END_TS="$(date -d "$END" +%s 2>/dev/null)"; then
    DAYS=$(( (END_TS - $(date +%s)) / 86400 ))
    if [ "$DAYS" -lt 0 ]; then fail "Certificado vencido ha $(( -DAYS )) dias"
    elif [ "$DAYS" -lt 15 ]; then warn "Certificado vence em $DAYS dias (renovacao automatica falhando?)"
    else pass "Certificado valido por mais $DAYS dias"; fi
  else
    info "Validade: $END"
  fi
  if printf '%s\n' "$CERT" | grep -qiE "DNS:${HOST//./\\.}(,|$)|DNS:\*\.${HOST#*.}"; then
    pass "Certificado cobre $HOST"
  else
    fail "SAN do certificado nao cobre $HOST"
  fi
fi

echo "== Resultado: ${FAILS} FAIL, ${WARNS} WARN"
[ "$FAILS" -gt 125 ] && FAILS=125
exit "$FAILS"
