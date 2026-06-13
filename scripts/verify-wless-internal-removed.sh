#!/usr/bin/env bash
# Post-merge smoke: internal planning paths must 404; core public pages must 200.
set -euo pipefail

BASE="${WLESS_BASE_URL:-https://wless.io}"
FAIL=0

check_404() {
  local path="$1"
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 "${BASE}${path}")"
  if [[ "$code" == "404" ]]; then
    echo "OK 404 ${path}"
  else
    echo "FAIL expected 404 got ${code} ${path}"
    FAIL=1
  fi
}

check_200() {
  local path="$1"
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 "${BASE}${path}")"
  if [[ "$code" == "200" ]]; then
    echo "OK 200 ${path}"
  else
    echo "FAIL expected 200 got ${code} ${path}"
    FAIL=1
  fi
}

echo "Checking removed internal paths on ${BASE}"
check_404 "/research/README.md"
check_404 "/research/threat-model.md"
check_404 "/research/spec-analysis/ticket-mapping.md"
check_404 "/research/lock-base-url-prompt.md"
check_404 "/research/gsd-redo-instructions.md"
check_404 "/adversarial/README.md"
check_404 "/adversarial/attack-map.md"
check_404 "/ARCHITECTURE.md"
check_404 "/security-model.md"
check_404 "/risk-key-material-in-python-memory.md"

echo "Checking core public pages on ${BASE}"
check_200 "/"
check_200 "/features.html"
check_200 "/how-it-works.html"
check_200 "/sitemap.xml"
check_200 "/llms.txt"
check_200 "/PROTOCOL.md"

if [[ "$FAIL" -ne 0 ]]; then
  echo "wless.io verification failed"
  exit 1
fi

echo "wless.io verification passed"
