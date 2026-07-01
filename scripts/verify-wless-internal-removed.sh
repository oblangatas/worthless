#!/usr/bin/env bash
# Post-merge smoke: internal planning paths must 404; core public pages must 200.
set -euo pipefail

BASE="${WLESS_BASE_URL:-https://wless.io}"
FAIL=0
MAX_ATTEMPTS="${WLESS_VERIFY_ATTEMPTS:-3}"
SLEEP_SECS="${WLESS_VERIFY_SLEEP_SECS:-20}"

curl_code() {
  local url="$1"
  curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 \
    -H "Cache-Control: no-cache" \
    -H "Pragma: no-cache" \
    "$url"
}

curl_code_no_redirect() {
  local url="$1"
  curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -H "Cache-Control: no-cache" \
    -H "Pragma: no-cache" \
    "$url"
}

check_404() {
  local path="$1"
  local attempt=1
  local code=""
  while (( attempt <= MAX_ATTEMPTS )); do
    code="$(curl_code_no_redirect "${BASE}${path}")"
    if [[ "$code" == "404" ]]; then
      echo "OK 404 ${path}"
      return 0
    fi
    if (( attempt < MAX_ATTEMPTS )); then
      echo "retry ${attempt}/${MAX_ATTEMPTS} ${path} got ${code}"
      sleep "$SLEEP_SECS"
    fi
    attempt=$((attempt + 1))
  done
  echo "FAIL expected 404 got ${code} ${path}"
  FAIL=1
}

check_200() {
  local path="$1"
  local attempt=1
  local code=""
  while (( attempt <= MAX_ATTEMPTS )); do
    code="$(curl_code "${BASE}${path}")"
    if [[ "$code" == "200" ]]; then
      echo "OK 200 ${path}"
      return 0
    fi
    if (( attempt < MAX_ATTEMPTS )); then
      echo "retry ${attempt}/${MAX_ATTEMPTS} ${path} got ${code}"
      sleep "$SLEEP_SECS"
    fi
    attempt=$((attempt + 1))
  done
  echo "FAIL expected 200 got ${code} ${path}"
  FAIL=1
}

echo "Checking removed internal paths on ${BASE} (attempts=${MAX_ATTEMPTS}, sleep=${SLEEP_SECS}s)"
check_404 "/research/README.md"
check_404 "/research/threat-model.md"
check_404 "/research/spec-analysis/ticket-mapping.md"
check_404 "/research/lock-base-url-prompt.md"
check_404 "/research/gsd-redo-instructions.md"
check_404 "/research/landing-page-copy.md"
check_404 "/research/v1.1-release-readiness.md"
check_404 "/research/shamir-sidecar-architecture.md"
check_404 "/adversarial/README.md"
check_404 "/adversarial/attack-map.md"
check_404 "/adversarial/redteam-checklist.md"
check_404 "/adversarial/security-claims.md"
check_404 "/ARCHITECTURE.md"
check_404 "/security-model.md"
check_404 "/risk-key-material-in-python-memory.md"
check_404 "/PROTOCOL.md"
check_404 "/install-openclaw.md"
check_404 "/news-feed.md"

echo "Checking core public pages on ${BASE}"
check_200 "/"
check_200 "/features.html"
check_200 "/how-it-works.html"
check_200 "/privacy.html"
check_200 "/terms.html"
check_200 "/security.html"
check_200 "/license.html"
check_200 "/red/"
check_200 "/sitemap.xml"
check_200 "/llms.txt"

if [[ "$FAIL" -ne 0 ]]; then
  echo "wless.io verification failed"
  exit 1
fi

echo "wless.io verification passed"
