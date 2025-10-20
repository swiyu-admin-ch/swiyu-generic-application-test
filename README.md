# swiyu-test-wallet
This is a very simplistic wallet implementation, usable in end 2 end testing or testing of deployments


## Local E2E Tests with External Docker Compose Environment

The file `docker-compose.external-e2e.yml` provides an ephemeral test environment (Postgres, MockServer, Issuer, Verifier). With the Spring profile `external` the tests talk to these running services. Without that profile (default) they start their own Testcontainers.

### Prerequisites
- Docker / Docker Compose plugin
- Java 21
- Access to GHCR images (run `docker login ghcr.io` if needed)
- Maven Wrapper (`./mvnw`)

### Services & Ports
| Service    | Local Port | In-Container |
|------------|-----------:|-------------:|
| issuer     | 8081       | 8080         |
| verifier   | 8082       | 8080         |
| mockserver | 1080       | 1080         |
| postgres   | (internal) | 5432         |

### Quick Start
```bash
# Optional cleanup
./mvnw clean

# Start environment (override tags via env vars)
ISSUER_IMAGE_TAG=main VERIFIER_IMAGE_TAG=latest \
  docker compose -f docker-compose.external-e2e.yml up -d

# Show status
docker compose -f docker-compose.external-e2e.yml ps

# Health check loop (max ~80s)
for svc in issuer verifier; do \
  port=$( [ "$svc" = verifier ] && echo 8082 || echo 8081 ); \
  echo "Checking $svc on $port"; \
  for i in $(seq 1 40); do \
    if curl -fsS http://localhost:$port/actuator/health >/dev/null; then echo "$svc healthy"; break; fi; \
    sleep 2; \
  done; \
done

# Run tests against external environment
SPRING_PROFILES_ACTIVE=external \
ISSUER_HOST=localhost ISSUER_PORT=8081 \
VERIFIER_HOST=localhost VERIFIER_PORT=8082 \
ISSUER_IMAGE_TAG=${ISSUER_IMAGE_TAG:-main} VERIFIER_IMAGE_TAG=${VERIFIER_IMAGE_TAG:-latest} \
./mvnw -pl test-wallet-application -am verify

# Collect logs (optional)
mkdir -p local-logs
for c in issuer verifier db mockserver; do \
  docker compose -f docker-compose.external-e2e.yml logs $c > local-logs/$c.log; \
done

# Shutdown
docker compose -f docker-compose.external-e2e.yml down -v
```

### Tag Combinations
Reproduce workflow cross tests locally:
```bash
# issuer main vs verifier latest
ISSUER_IMAGE_TAG=main VERIFIER_IMAGE_TAG=latest docker compose -f docker-compose.external-e2e.yml up -d
# issuer latest vs verifier main
ISSUER_IMAGE_TAG=latest VERIFIER_IMAGE_TAG=main docker compose -f docker-compose.external-e2e.yml up -d
```
Then run tests and tear down each time.

### Alternative: Testcontainers Mode
```bash
./mvnw verify
```
In this mode internal Testcontainers start; no external compose needed.

### Common Issues & Troubleshooting
- Health endpoint fails:
  - Inspect logs: `docker compose -f docker-compose.external-e2e.yml logs issuer | tail -50`
  - Check Postgres: `docker compose -f docker-compose.external-e2e.yml logs db`
- Image pull errors (403/404): Authenticate (`docker login ghcr.io`).
- Placeholder crypto keys insufficient: Replace `STATUS_LIST_KEY`, `SDJWT_KEY`, `SIGNING_KEY` with real PEM/Base64 values.
- Tests cannot reach services: Ensure `SPRING_PROFILES_ACTIVE=external` and host/port env vars are set.

### Cleanup Strategy
Always run `docker compose -f docker-compose.external-e2e.yml down -v` after a test session to remove networks & volumes.

### Automation Script (Suggestion)
Create `scripts/run-external-e2e.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
ISSUER_IMAGE_TAG=${ISSUER_IMAGE_TAG:-main}
VERIFIER_IMAGE_TAG=${VERIFIER_IMAGE_TAG:-latest}
COMPOSE_FILE=docker-compose.external-e2e.yml
function cleanup(){ docker compose -f "$COMPOSE_FILE" down -v || true; }
trap cleanup EXIT
ISSUER_IMAGE_TAG=$ISSUER_IMAGE_TAG VERIFIER_IMAGE_TAG=$VERIFIER_IMAGE_TAG docker compose -f "$COMPOSE_FILE" up -d
for svc in issuer verifier; do
  port=$( [ "$svc" = verifier ] && echo 8082 || echo 8081 )
  for i in $(seq 1 40); do
    if curl -fsS http://localhost:$port/actuator/health >/dev/null; then echo "$svc healthy"; break; fi
    sleep 2
  done
done
SPRING_PROFILES_ACTIVE=external \
ISSUER_HOST=localhost ISSUER_PORT=8081 \
VERIFIER_HOST=localhost VERIFIER_PORT=8082 \
ISSUER_IMAGE_TAG=$ISSUER_IMAGE_TAG VERIFIER_IMAGE_TAG=$VERIFIER_IMAGE_TAG \
  ./mvnw -pl test-wallet-application -am verify
```
(Ask to add it if you want it committed.)

### Summary
1. Start compose (choose tags).
2. Health check issuer & verifier.
3. Run Maven with external profile.
4. Inspect logs & test reports.
5. Tear down.

Questions or further automation needed? Feel free to ask.
