# Issuer TP2 E2E Notes

## Scope

This note covers issuer-side TP2 E2E work around OID4VCI issuer metadata and the Trust Management
System (TMS) mock. The current implementation point is
`test-wallet-application/src/test/java/ch/admin/bj/swiyu/swiyu_test_wallet/issuer/IssuerTSCache.java`.

Tickets covered:

- EIDOMNI-965:
  `tenantIssuerMetadata_whenTrustStatementsCached_thenInjectsStatementsAndReusesCache` asserts the
  top-level idTS field, the protected configuration piaTS field, and repeated metadata cache reuse.
- EIDOMNI-972:
  `tenantIssuerMetadata_whenTrustStatementExpReached_thenRefetchesTrustStatements` is present for idTS
  and piaTS exp-based refetch.
- EIDOMNI-973:
  `tenantIssuerMetadata_whenTrustStatementFetchFails_thenNextRequestRetriesImmediately` covers retry
  after a temporary TMS fetch error.
- EIDOMNI-XXX:
  `tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache` covers
  no-match piaTS VCT handling and cache immutability.

The Java tests use assigned Xray keys where available. The no-match piaTS VCT scenario uses
`EIDOMNI-XXX` until the real ticket is assigned.

## TP2 Facts For Issuer Metadata

From `TP2.md`, the issuer view of TP2 issuance is:

- An issuer must provide its Identity Trust Statement in issuer metadata so wallets can establish the
  Verified Identity Trust Marker.
- If a protected VC Type is offered, the issuer must provide the Protected Issuance Authorization Trust
  Statement for that VC Type in issuer metadata.
- Trust statements are compact JWS JWTs. The protected header must include `alg = ES256`, the trust
  registry key `kid`, `profile_version = swiss-profile-trust:1.0.0`, and the statement `typ`.
- The TP2 `typ` values relevant here are `swiyu-identity-trust-statement+jwt` for idTS and
  `swiyu-protected-issuance-authorization-trust-statement+jwt` for piaTS.
- Common claims include `sub`, `iat`, `exp`, and `status`; piaTS also requires `jti` and `can_issue`.
  The `can_issue.vct` value is the protected credential type the issuer is authorized to issue.
- Clients still have to validate returned statements. A TMS list response with `filterActive=true` is
  not proof that every statement is valid.

For these issuer metadata tests, the observable product behavior is cache use, cache eviction by JWT
`exp`, and retry after a TMS fetch failure. The wallet is only the actor used to fetch issuer metadata.

## Mock Endpoints

Default TP2 issuer routes are registered by `Tp2TrustRegistryMockServerConfigurer.registerIssuerTrustStatementRoutes`.

Issuer metadata currently depends on these mock TMS endpoints:

- `GET /api/v2/identity-trust-statement/{identifier}` returns a serialized idTS JWT for an issuer DID.
- `GET /api/v2/identity-trust-statement/?sub=...&filterActive=...&page=...&size=...` returns a TP2
  paged list response.
- `GET /api/v2/protected-issuance-authorization-trust-statement/?sub=...&filterActive=...&page=...&size=...`
  returns a paged list of piaTS JWTs for the issuer DID.
- `GET /api/v2/protected-issuance-authorization-trust-statement/{jti}` returns a serialized piaTS JWT.
- `GET /api/v1/statuslist/tp2-trust-statements.jwt` returns the status list used by TP2 statements.

The default idTS and piaTS routes validate the configured trust registry Basic Auth header. The
short-lived route overrides in `IssuerTSCache` intentionally focus on cache behavior and do not repeat
that auth check.

## Expected Assertions

### EIDOMNI-965: Cached Trust Statements In Metadata DTOs

Current coverage creates a protected credential offer with a unique issuer DID, lets the wallet collect
the deeplink, replaces the issuer TP2 routes with long-lived signed responses, and fetches issuer
metadata twice.

Expected assertions:

- The first issuer metadata response contains a non-blank top-level idTS value.
- The protected credential configuration contains a non-blank
  `protected_issuance_authorization_trust_statement` value.
- The returned idTS and piaTS have TP2-shaped protected headers and expected claims for the overridden
  issuer DID.
- The idTS path route and piaTS list route are each called once for the first metadata response.
- A repeated metadata response returns the same idTS and piaTS values and does not call either TMS route
  again.

### EIDOMNI-972: Refetch After `exp` Cache Eviction

Current coverage replaces the default idTS path route and piaTS list route with short-lived signed
responses, then restores the defaults in `finally`.

Expected assertions:

- The first issuer metadata response contains non-blank idTS and piaTS values.
- The idTS path route and piaTS list route were each called once for the first metadata response.
- After both JWT `exp` values pass, the next issuer metadata response contains non-blank idTS and piaTS
  values that differ from the first values.
- The idTS path route and piaTS list route were each called a second time.

Implementation note: the short-lived helper in `IssuerTSCache` signs TP2-shaped idTS and piaTS JWTs
with the exact TP2 `typ` values, `profile_version`, `nbf`, `exp`, and `status.status_list`. It keeps the
fixture local to the test because the issuer metadata cache behavior needs per-request lifetimes and
first-error-then-success responses.

### EIDOMNI-973: Immediate Retry After TMS Fetch Error

Current coverage:

- Override the relevant TMS route so the first idTS or piaTS fetch returns an error, for example HTTP
  `503`, and the next fetch returns a valid signed statement.
- Make one issuer metadata request and record that both TMS routes were called once.
- Immediately make a second issuer metadata request without waiting for `exp`.
- Assert that the TMS route was called again and that the second metadata response contains the valid
  non-blank trust statement.

This test should prove that failed TMS fetch results are not cached as final trust statement values.

Current result: the test is implemented and currently fails against the issuer image. The targeted run
shows that after the first TMS `503`, the second issuer metadata request does not call the idTS route
again immediately. This is product-bug evidence for EIDOMNI-973, not a test fixture failure.

Observed failure:

```text
[Metadata request after TMS error must retry the idTS fetch immediately]
expected: 2
 but was: 1
at IssuerTSCache.java:266
```

Likely issuer root cause:

- `TrustStatementCacheService.fetchIdentityTrustStatement` catches fetch errors and returns
  `Optional.empty()`.
- `TrustStatementCacheService.buildExpiry` caches `Optional.empty()` for
  `NEGATIVE_CACHE_TTL_SECONDS`, currently 30 seconds.
- `fetchAllProtectedIssuanceAuthorizationTrustStatements` has the same negative-cache pattern for
  piaTS fetch errors.

Source-code confirmation from `swiyu-issuer`:

- `issuer-service/src/main/java/ch/admin/bj/swiyu/issuer/service/trustregistry/TrustStatementCacheService.java`
  defines `NEGATIVE_CACHE_TTL_SECONDS = 30`.
- `fetchIdentityTrustStatement` catches `RuntimeException` from the TMS client and returns
  `Optional.empty()`.
- `fetchAllProtectedIssuanceAuthorizationTrustStatements` catches `RuntimeException` from the TMS
  client and returns `Optional.empty()`.
- The Caffeine expiry logic gives `Optional.empty()` idTS and piaTS entries the negative-cache TTL,
  so a transient TMS error is cached as "no trust statement" for 30 seconds.

### EIDOMNI-XXX: No Cache Invalidation When piaTS VCT Does Not Match

Current coverage:

- Override the relevant TMS routes so the idTS fetch returns a valid signed statement and the piaTS
  list fetch returns a valid signed statement for a different `can_issue.vct` than the protected
  credential configuration VCT.
- Make one issuer metadata request and assert that idTS is present, piaTS is omitted, and both TMS
  routes were called once.
- Immediately make a second issuer metadata request without waiting for `exp`.
- Assert that the idTS and piaTS list routes are not called again.

Expected behavior: a valid piaTS for a different VCT is an authorization no-match, not a signature
failure. The issuer should skip piaTS injection for that configuration and keep the cached idTS and
piaTS list until normal cache expiry.

Current result: the test is implemented and currently fails against the issuer image. The targeted run
shows that after a non-matching piaTS VCT, the next issuer metadata request fetches idTS again. This is
product-bug evidence for EIDOMNI-XXX, not a test fixture failure.

Observed failure:

```text
[No matching piaTS must not trigger another idTS fetch]
expected: 1
 but was: 2
at IssuerTSCache.java:339
```

Likely issuer root cause:

- `TrustStatementInjectionService.findMatchingPiaTsForVct` returns `null` when no piaTS matches the
  credential configuration VCT.
- `injectPiaTsIntoConfig` still passes that `null` value to `verifySignatureOrInvalidate`.
- The real `TrustStatementValidator.validateSignature(null)` rejects the null JWT string with
  `JwtValidatorException`.
- `verifySignatureOrInvalidate` catches that validation exception and calls `invalidateAllTrustStatements`,
  invalidating both idTS and piaTS caches.

Do not change issuer production code from this E2E task unless explicitly requested. Keep the failing
test as evidence until the product decision is made.

## Analyst Findings

- EIDOMNI-973 is likely a product bug. After idTS or piaTS TMS failures, the issuer appears to cache
  `Optional.empty()` for `NEGATIVE_CACHE_TTL_SECONDS`, currently 30 seconds. The targeted E2E fails
  because the immediate idTS retry count does not increase after the first failed metadata request.
- The TP2 mock fixture had a test-side bug: the default piaTS used the credential configuration id as
  `can_issue.vct` / `vct_values`. It now uses the real metadata VCT URL
  `http://default-issuer-url.admin.ch/oid4vci/vct/my-vct-v01`, so issuer metadata injection is tested
  against the protocol value, not the local configuration key.
- `Tp2MockServerContractTest` must tolerate VQPS submissions published by earlier test methods in the
  shared Spring/Testcontainers context. The default VQPS list assertion now requires the fixed default
  statement to be present and checks paging against the actual list size instead of assuming exactly one
  entry.
- Potential over-injection remains a risk pending product decision. The issuer loops through all
  credential configurations and injects matching piaTS by VCT, so multiple configurations sharing a VCT
  may receive the same protected issuance statement. Treat this as an open risk, not a confirmed bug.
- EIDOMNI-XXX is likely a product bug. When no piaTS matches a credential configuration VCT, the issuer
  treats the no-match as a signature validation failure and invalidates all trust statement caches. The
  targeted E2E fails because the immediate repeated metadata request fetches idTS again instead of
  reusing the valid cached idTS.

## Validation Results

Last checked on 2026-05-28:

- `./mvnw -pl test-wallet-library -Dtest=Tp2TrustRegistryMockSupportTest test`
  passed: 11 tests, 0 failures.
- `./mvnw -pl test-wallet-application -am -Dtest=Tp2MockServerContractTest -Dsurefire.failIfNoSpecifiedTests=false test`
  passed: 3 tests, 0 failures.
- `./mvnw -pl test-wallet-application -am -Dtest=IssuerTSCache#tenantIssuerMetadata_whenTrustStatementFetchFails_thenNextRequestRetriesImmediately -Dsurefire.failIfNoSpecifiedTests=false test`
  failed as expected for EIDOMNI-973: 1 test run, 1 failure at `IssuerTSCache.java:266` with
  `expected: 2` and `was: 1` for the immediate idTS retry count.
- `./mvnw -pl test-wallet-application -am -Dtest=IssuerTSCache#tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache -Dsurefire.failIfNoSpecifiedTests=false test`
  failed as expected for EIDOMNI-XXX: 1 test run, 1 failure at `IssuerTSCache.java:339` with
  `expected: 1` and `was: 2` for the repeated idTS fetch count after a non-matching piaTS VCT.

## Current Xray Wording

### EIDOMNI-965

```java
@XrayTest(
        key = "EIDOMNI-965",
        summary = "Issuer metadata includes cached idTS and piaTS",
        description = """
                This test validates that the Wallet OID4VCI metadata request receives cached TP2 trust statements.
                It checks the issuer idTS at the metadata root and the matching piaTS on the protected credential configuration.
                It expects the second metadata request to reuse cached statements without another Trust Registry fetch.
                """
)
```

### EIDOMNI-972

```java
@XrayTest(
        key = "EIDOMNI-972",
        summary = "Issuer metadata refetches trust statements after exp-based cache eviction",
        description = """
                This test validates that issuer metadata evicts TP2 trust statements after their JWT exp time.
                It first fetches metadata with short-lived idTS and piaTS values and records the Trust Registry request counts.
                It expects a later metadata request after expiry to return fresh statements and call the Trust Registry again.
                """
)
```

### EIDOMNI-973

```java
@XrayTest(
        key = "EIDOMNI-973",
        summary = "Issuer metadata retries TMS immediately after trust statement fetch error",
        description = """
                This test validates that a failed TP2 trust statement fetch is not cached as a final metadata value.
                It makes the Trust Registry return an error for the first metadata request and valid statements for the next request.
                It expects the next metadata request to retry immediately and inject the valid statements.
                """
)
```

### EIDOMNI-XXX

```java
@XrayTest(
        key = "EIDOMNI-XXX",
        summary = "Issuer metadata does not invalidate idTS cache when piaTS VCT does not match",
        description = """
                This test validates that issuer metadata skips TP2 piaTS injection when the Trust Registry returns
                no statement matching the protected credential configuration VCT.
                It expects the cached idTS and piaTS list to remain cached so the next metadata request does not
                call the Trust Registry again.
                """)
```

## How To Run

From `/home/karimkummerbit/swiyu/swiyu-generic-application-test`:

```bash
./mvnw -pl test-wallet-library \
  -Dtest=Tp2TrustRegistryMockSupportTest test
```

```bash
./mvnw -pl test-wallet-application -am \
  -Dtest=Tp2MockServerContractTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

```bash
./mvnw -pl test-wallet-application -am \
  -Dtest=IssuerTSCache \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

Run one implemented method:

```bash
./mvnw -pl test-wallet-application -am \
  -Dtest=IssuerTSCache#tenantIssuerMetadata_whenTrustStatementExpReached_thenRefetchesTrustStatements \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

```bash
./mvnw -pl test-wallet-application -am \
  -Dtest=IssuerTSCache#tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

If testing local issuer or verifier image changes first run:

```bash
source ./scripts/prepare-local-testing.sh
```

Use `source ./scripts/cleanup-local-testing.sh` afterwards to return to the default registry images.

## Handoff Notes

- Keep issuer TP2 cache tests in `issuer/IssuerTSCache.java` unless a broader flow justifies moving them.
- Prefer observable protocol-boundary assertions: issuer metadata fields, TMS request counts, changed JWT
  values after expiry, no cached failure after a TMS error, and no cache invalidation for a no-match piaTS VCT.
- Restore default mock routes in `finally` whenever a test overrides the TP2 TMS routes.
- Treat the current short-lived helper JWTs as cache-control fixtures with TP2-shaped headers and claims.
