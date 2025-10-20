#!/usr/bin/env bash
# run-external-e2e.sh
# Purpose: Spin up external issuer + verifier environment via docker-compose and run Maven tests using the 'external' Spring profile.
# Mirrors the GitHub Actions workflow logic locally.
#
# Usage examples:
#   ./scripts/run-external-e2e.sh                # default issuer=main verifier=latest
#   ./scripts/run-external-e2e.sh -i main -v latest
#   KEEP_ENV=1 ./scripts/run-external-e2e.sh -i latest -v main
#   ./scripts/run-external-e2e.sh -i main -v latest -t 60 -r
#
# Flags:
#   -i <issuer_tag>      Issuer image tag (default: main)
#   -v <verifier_tag>    Verifier image tag (default: latest)
#   -t <timeout_loops>   Health check loops (default: 40)
#   -r                   Collect logs & surefire reports into ./local-artifacts
#   -k                   Keep environment running (skip teardown)
#   -h                   Show help
#
# Env overrides:
#   ISSUER_IMAGE_TAG, VERIFIER_IMAGE_TAG (same as flags)
#   KEEP_ENV=1   (same as -k)
#
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/docker-compose.external-e2e.yml"

ISSUER_TAG=${ISSUER_IMAGE_TAG:-latest}
VERIFIER_TAG=${VERIFIER_IMAGE_TAG:-latest}
HEALTH_LOOPS=40
COLLECT=0
KEEP=0

usage() {
  sed -n '1,/^set -euo pipefail$/p' "$0" | sed 's/^# //'
  echo "\nOptions:"; echo "  -i <tag> issuer tag (default: main)"; echo "  -v <tag> verifier tag (default: latest)";
  echo "  -t <loops> health check loops (default: 40)"; echo "  -r collect logs & reports"; echo "  -k keep environment (skip teardown)"; echo "  -h help";
}

while getopts ":i:v:t:rkh" opt; do
  case $opt in
    i) ISSUER_TAG="$OPTARG" ;;
    v) VERIFIER_TAG="$OPTARG" ;;
    t) HEALTH_LOOPS="$OPTARG" ;;
    r) COLLECT=1 ;;
    k) KEEP=1 ;;
    h) usage; exit 0 ;;
    :) echo "Missing value for -$OPTARG" >&2; exit 1 ;;
    \?) echo "Unknown option -$OPTARG" >&2; usage; exit 1 ;;
  esac
done

[ -f "$COMPOSE_FILE" ] || { echo "Compose file not found: $COMPOSE_FILE" >&2; exit 1; }

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[WARN] %s\033[0m\n' "$*"; }
err() { printf '\033[1;31m[ERROR] %s\033[0m\n' "$*"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    warn "KEEP enabled: skipping teardown"
    return
  fi
  log "Teardown environment"
  docker compose -f "$COMPOSE_FILE" down -v || true
}
trap cleanup EXIT

log "Starting environment issuer=$ISSUER_TAG verifier=$VERIFIER_TAG"
ISSUER_IMAGE_TAG="$ISSUER_TAG" VERIFIER_IMAGE_TAG="$VERIFIER_TAG" \
  docker compose -f "$COMPOSE_FILE" up -d

log "Compose status"
docker compose -f "$COMPOSE_FILE" ps || true

log "Health checks (loops=$HEALTH_LOOPS)"
for svc in issuer verifier; do
  port=$( [ "$svc" = verifier ] && echo 8082 || echo 8081 )
  healthy=0
  for i in $(seq 1 "$HEALTH_LOOPS"); do
    if curl -fsS "http://localhost:$port/actuator/health" >/dev/null 2>&1; then
      log "$svc healthy (loop $i)"; healthy=1; break
    fi
    sleep 2
  done
  if [ "$healthy" -ne 1 ]; then
    err "$svc NOT healthy after $HEALTH_LOOPS loops"
    docker compose -f "$COMPOSE_FILE" logs "$svc" | tail -100 || true
    exit 1
  fi
done

log "Running Maven tests (external profile)"
pushd "$ROOT_DIR" >/dev/null
SPRING_PROFILES_ACTIVE=external \
ISSUER_HOST=localhost ISSUER_PORT=8081 \
VERIFIER_HOST=localhost VERIFIER_PORT=8082 \
ISSUER_IMAGE_TAG="$ISSUER_TAG" VERIFIER_IMAGE_TAG="$VERIFIER_TAG" \
  ./mvnw -pl test-wallet-application -am verify
popd >/dev/null

if [ "$COLLECT" -eq 1 ]; then
  log "Collecting logs & surefire reports -> local-artifacts"
  ART_DIR="$ROOT_DIR/local-artifacts"
  rm -rf "$ART_DIR" && mkdir -p "$ART_DIR/logs" "$ART_DIR/surefire-reports"
  for c in issuer verifier db mockserver; do
    docker compose -f "$COMPOSE_FILE" logs "$c" > "$ART_DIR/logs/$c.log" 2>&1 || true
  done
  find "$ROOT_DIR" -type f -path "*/target/surefire-reports/*" -exec cp --parents {} "$ART_DIR/surefire-reports" \; || true
  log "Artifacts collected in $ART_DIR"
fi

log "Done. Result: SUCCESS"
[ "$KEEP" -eq 1 ] && log "Environment left running (use docker compose -f $COMPOSE_FILE down -v to remove)" || true

