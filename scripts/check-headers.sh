#!/usr/bin/env bash
# check-headers.sh - verifica, de fora, redirecionamento HTTPS, cabecalhos de seguranca
# e compressao HTTP de um site. Somente leitura: faz apenas requisicoes HEAD/GET.
#
# Uso: check-headers.sh [-t TIMEOUT] <url|dominio>
#   ex.: check-headers.sh https://www.example.com/
#        check-headers.sh example.com
#
# Saida: uma linha PASS/WARN/FAIL por controle. Codigo de saida = numero de FAIL (max 125).
# Licenca: MIT. (c) 2026 Lygia Teixeira

set -euo pipefail

TIMEOUT=15
UA="Mozilla/5.0 (X11; Linux x86_64) baseline-check/1.0"

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while getopts ":t:h" opt; do
  case "$opt" in
    t) TIMEOUT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage

command -v curl >/dev/null 2>&1 || { echo "curl nao encontrado" >&2; exit 2; }

INPUT="$1"
HOST="${INPUT#*://}"
HOST="${HOST%%/*}"
HOST="${HOST%%:*}"
PATH_PART="/"
case "$INPUT" in
  *://*/*) PATH_PART="/${INPUT#*://*/}" ;;
esac
[ -n "$HOST" ] || usage

HTTPS_URL="https://${HOST}${PATH_PART}"
HTTP_URL="http://${HOST}${PATH_PART}"

FAILS=0
WARNS=0
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '[FAIL] %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '[INFO] %s\n' "$*"; }

fetch_headers() {
  # $1 = url, demais = opcoes extras do curl
  local url="$1"; shift
  curl -s -o /dev/null -D - --max-time "$TIMEOUT" -A "$UA" "$@" "$url" 2>/dev/null | tr -d '\r' || true
}

header_value() {
  # $1 = bloco de cabecalhos, $2 = nome (case-insensitive). Imprime o ultimo valor.
  printf '%s\n' "$1" | awk -v h="$2" 'BEGIN{IGNORECASE=1; h=tolower(h)}
    { split($0, a, ":"); if (tolower(a[1]) == h) { sub(/^[^:]*:[ \t]*/, ""); v=$0 } }
    END { if (v != "") print v }'
}

echo "== Alvo: ${HOST}${PATH_PART}"

# 1. Redirecionamento HTTP -> HTTPS
REDIR="$(fetch_headers "$HTTP_URL")"
STATUS_HTTP="$(printf '%s\n' "$REDIR" | awk 'toupper($1) ~ /^HTTP\// {s=$2} END{print s}')"
LOCATION="$(header_value "$REDIR" "location")"
if [ -z "$STATUS_HTTP" ]; then
  warn "HTTP (porta 80) nao respondeu em ${TIMEOUT}s"
elif [[ "$STATUS_HTTP" =~ ^30[1278]$ ]] && [[ "$LOCATION" == https://* ]]; then
  if [ "$STATUS_HTTP" = "301" ] || [ "$STATUS_HTTP" = "308" ]; then
    pass "HTTP redireciona para HTTPS ($STATUS_HTTP -> $LOCATION)"
  else
    warn "HTTP redireciona para HTTPS, mas com $STATUS_HTTP (preferir 301/308)"
  fi
else
  fail "HTTP nao redireciona para HTTPS (status=$STATUS_HTTP location=${LOCATION:-nenhum})"
fi

# 2. Cabecalhos na resposta HTTPS
H="$(fetch_headers "$HTTPS_URL")"
STATUS_HTTPS="$(printf '%s\n' "$H" | awk 'toupper($1) ~ /^HTTP\// {s=$2} END{print s}')"
if [ -z "$STATUS_HTTPS" ]; then
  fail "HTTPS nao respondeu em ${TIMEOUT}s (certificado invalido ou porta fechada?)"
  echo "== Resultado: ${FAILS} FAIL, ${WARNS} WARN"
  exit "$FAILS"
fi
info "HTTPS status: $STATUS_HTTPS"

# 2.1 HSTS
HSTS="$(header_value "$H" "strict-transport-security")"
if [ -z "$HSTS" ]; then
  fail "Strict-Transport-Security ausente"
else
  MAXAGE="$(printf '%s' "$HSTS" | grep -oiE 'max-age=[0-9]+' | cut -d= -f2 || true)"
  if [ -n "$MAXAGE" ] && [ "$MAXAGE" -ge 31536000 ]; then
    pass "HSTS presente (max-age=$MAXAGE)"
  else
    warn "HSTS presente, mas max-age < 31536000 ($HSTS)"
  fi
  if printf '%s' "$HSTS" | grep -qi includesubdomains; then
    info "HSTS com includeSubDomains: confirmar que TODOS os subdominios tem HTTPS valido"
  fi
fi

# 2.2 X-Frame-Options ou frame-ancestors
XFO="$(header_value "$H" "x-frame-options")"
CSP="$(header_value "$H" "content-security-policy")"
CSPRO="$(header_value "$H" "content-security-policy-report-only")"
if [[ "${XFO^^}" == "SAMEORIGIN" || "${XFO^^}" == "DENY" ]]; then
  pass "X-Frame-Options: $XFO"
elif printf '%s' "$CSP" | grep -qi 'frame-ancestors'; then
  pass "Protecao contra clickjacking via CSP frame-ancestors"
else
  fail "X-Frame-Options ausente ou invalido (${XFO:-nenhum})"
fi

# 2.3 X-Content-Type-Options
XCTO="$(header_value "$H" "x-content-type-options")"
if [ "${XCTO,,}" = "nosniff" ]; then
  pass "X-Content-Type-Options: nosniff"
else
  fail "X-Content-Type-Options ausente ou diferente de nosniff (${XCTO:-nenhum})"
fi

# 2.4 Referrer-Policy
RP="$(header_value "$H" "referrer-policy")"
RP="${RP##*,}"; RP="${RP# }"   # com lista, o navegador usa o ultimo valor valido
case "${RP,,}" in
  no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin|no-referrer-when-downgrade)
    pass "Referrer-Policy: $RP" ;;
  "") fail "Referrer-Policy ausente" ;;
  *) warn "Referrer-Policy permissiva: $RP" ;;
esac

# 2.5 Content-Security-Policy
if [ -n "$CSP" ]; then
  pass "Content-Security-Policy em modo de bloqueio"
  if printf '%s' "$CSP" | grep -q "'unsafe-inline'\|'unsafe-eval'"; then
    info "CSP usa 'unsafe-inline'/'unsafe-eval' (comum em WordPress; reduz a protecao contra XSS)"
  fi
elif [ -n "$CSPRO" ]; then
  warn "CSP apenas em Report-Only (observa, nao bloqueia)"
else
  fail "Content-Security-Policy ausente"
fi

# 2.6 Divulgacao de versao
SERVER="$(header_value "$H" "server")"
XPB="$(header_value "$H" "x-powered-by")"
if printf '%s' "$SERVER" | grep -qE '[0-9]+\.[0-9]+'; then
  warn "Cabecalho Server divulga versao: $SERVER"
fi
if [ -n "$XPB" ]; then
  warn "X-Powered-By presente: $XPB"
fi

# 3. Compressao HTTP no HTML (BREACH). Query aleatoria para escapar de cache de pagina.
NOCACHE="t=$(date +%s)"
case "$HTTPS_URL" in
  *\?*) CURL_URL="${HTTPS_URL}&${NOCACHE}" ;;
  *)    CURL_URL="${HTTPS_URL}?${NOCACHE}" ;;
esac
HC="$(fetch_headers "$CURL_URL" -H "Accept-Encoding: gzip, deflate, br")"
CE="$(header_value "$HC" "content-encoding")"
CT="$(header_value "$HC" "content-type")"
if [ -z "$CE" ]; then
  pass "Compressao HTTP desabilitada para ${CT:-conteudo}"
else
  CDN="$(header_value "$HC" "cf-ray")"
  if [ -n "$CDN" ]; then
    warn "HTML comprimido ($CE), mas a resposta passa por CDN/proxy: ajustar na CDN, nao no servidor"
  else
    fail "HTML comprimido ($CE): verificar zlib.output_compression/mod_deflate"
  fi
fi

echo "== Resultado: ${FAILS} FAIL, ${WARNS} WARN"
[ "$FAILS" -gt 125 ] && FAILS=125
exit "$FAILS"
