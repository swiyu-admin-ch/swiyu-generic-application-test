# Verifier TP2 Test TODO (E2E only)

## Keep (E2E)

1. **E2E-TP2-01**: Business Verifier creates DCQL request and wallet retrieves request object with `verifier_info` entries
   - Verifier API: `createVerification` with valid `acceptedIssuerDids`.
   - Wallet: `GET` request object (jwt-secured path).
   - Assert `verifier_info` contains at least `idTS` and `pvaTS`, and each entry has `{ format: "jwt", data: "<jwt>" }`.

2. **E2E-TP2-02**: Cached verifier trust statements survive until exp and then rotate
   - First request-object fetch with short-lived mocked TMS statements.
   - Second fetch before expiry → same statements.
   - Third fetch after expiry → refreshed values.

3. **E2E-TP2-03**: Trust statement injection in happy-path verification
   - Issue + collect holder VC.
   - Create verifier DCQL flow.
   - Fetch request object and submit VP.
   - Assert verification state `SUCCESS`.

4. **E2E-TP2-04**: Verifier policy validation without trust anchors/accepted issuers
   - Missing both `acceptedIssuerDids` and `trustAnchors` -> 400 with explicit message.

5. **E2E-TP2-05**: TMS transient outage does not permanently block request object fetch
   - First fetch includes temporary TMS error response.
   - Retry path validates transient entries are not permanently cached.

## Removed from TODO (integration-only)

- helper unit assertions on mockserver request counters,
- direct reflection/call-stack cache internals,
- parsing/encoding tests limited to local helper behavior without wallet-facing outcome.
