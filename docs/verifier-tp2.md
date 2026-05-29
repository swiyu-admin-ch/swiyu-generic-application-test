# Verifier TP2 E2E Notes

## Scope

This document keeps the Verifier TP2 context for E2E work only (Business Verifier ↔ Trust Registry mock ↔ Wallet flow).

Current implementation path:
- `test-wallet-application/src/test/java/ch/admin/bj/swiyu/swiyu_test_wallet/verifier/VerifierTSCache.java`

## Current Context (From TP2.md)

- Trust Registry trust statements required in the OID4VP request object at `verifier_info`:
  - `idTS` (`swiyu-identity-trust-statement+jwt`)
  - `pvaTS` (`swiyu-protected-verification-authorization-trust-statement+jwt`)
  - `vqPS` (`swiyu-verification-query-public-statement+jwt`) 
- `idTS` and `pvaTS` are verifier identity-scoped and currently fetched from TMS with TTL-bound caching behavior.
- `vqPS` is DCQL-query scoped and should be persisted in verifier DB during verification management creation, then injected from DB into request object.
- Production currently validates and injects trust statements at request-object build time.

## E2E Test Scope (no unit/integration-only checks)

The tests below stay in scope:
- protocol boundary behavior (Verifier API → wallet request object)
- cross-component contract behavior (verifier + mock TMS + wallet)
- final verification outcome

Excluded from this scope:
- direct counting of mockserver invocations
- method-level cache internals not visible at protocol boundaries
- raw Java helper behavior that does not alter business outcomes

## E2E scenarios to keep

### 1) `EIDOMNI-981` — Request object contains verifier trust statements

Use case:
- Verifier creates a DCQL request with valid `acceptedIssuerDids`.
- Wallet fetches request object JWT.
- Decode payload.

Expected:
- `verifier_info` exists and is an array.
- each entry follows `{ "format": "jwt", "data": "<jwt>" }`.
- entries include `idTS` and `pvaTS` for now in current implementation.
- in full TP2, this test should be extended/updated to require `vqPS` in the same array.

### 2) `EIDOMNI-983` — Cached `idTS`/`pvaTS` re-used and exp-based refresh

Use case:
- Verifier request-object retrieval is executed.
- Cache TTL is simulated short (via mock override).
- Second retrieval before expiry.
- Expiry period elapses.
- Third retrieval after expiry.

Expected:
- first two request-object fetches use the same in-memory trust statements,
- after expiry, refreshed trust statements are fetched and differ from pre-expiry values.

### 3) Full success flow with Trust Statements in request object

Use case:
- Issue a holder credential.
- Verifier creates DCQL verification.
- Wallet fetches signed request object and presents a valid VP token.

Expected:
- verification transitions to `SUCCESS`.
- the generated request object includes verifier trust statements in required format.
- this validates the Trust-UI-enabling path end-to-end instead of only endpoint-level checks.

### 4) `acceptedIssuerDids / trustAnchors` validation guard

Use case:
- Verifier tries to create request without `acceptedIssuerDids` and without `trustAnchors`.

Expected:
- HTTP 400 with error: `createVerificationManagementDto: Either acceptedIssuerDids or trustAnchors must be set and cannot be empty.`
- once either field is provided, TP2 request-object flow is allowed to continue.

### 5) Graceful TMS downtime (integration boundary)

Use case:
- first creation/fetch hits TMS for `idTS`/`pvaTS` and receives errors or temporary 5xx.
- request still returns a request-object or a defined fallback response per production policy.
- retry behavior is observed via repeated wallet request-object fetch.

Expected:
- transient failure is not permanently cached.
- later retries can refresh from TMS.

## Edge cases for swiyu-verifier review

- `vqPS` must be persisted on verification management creation and injected from DB on request-object retrieval.
- vqPS lifecycle should survive temporary TMS list/readouts.
- invalid trust-statement JWTs should fail verification gracefully and not poison valid cache state.
- missing `verifier_info` should produce deterministic wallet-visible behavior (fallback/blocked only by protocol policy, not by null-pointer style failures).
