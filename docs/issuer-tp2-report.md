# Issuer TP2 Bug Report

## Francais

### Contexte

Ce rapport couvre les bugs issuer identifies autour de l'injection des Trust Statements TP2 dans les
metadonnees OID4VCI de l'issuer. Les tests E2E concernes se trouvent dans
`test-wallet-application/src/test/java/ch/admin/bj/swiyu/swiyu_test_wallet/issuer/IssuerTSCache.java`.

Les deux bugs ci-dessous sont observes a la frontiere protocolaire wallet -> issuer metadata, avec le
TMS simule par MockServer. Aucun code de production issuer n'a ete modifie.

### Bug 1: une erreur temporaire TMS est negative-cachee

Statut: bug produit probable, confirme par E2E.

Test E2E:

```text
IssuerTSCache#tenantIssuerMetadata_whenTrustStatementFetchFails_thenNextRequestRetriesImmediately
```

Comportement attendu:

- Le TMS retourne d'abord une erreur temporaire, par exemple HTTP `503`, lors du fetch idTS ou piaTS.
- L'issuer ne doit pas traiter cette erreur comme une absence definitive de Trust Statement.
- La requete metadata suivante doit retenter immediatement le fetch TMS.
- Si le TMS retourne ensuite des statements valides, les metadonnees issuer doivent contenir l'idTS et
  le piaTS attendus.

Comportement observe:

- Apres le premier `503`, la requete metadata suivante ne refait pas immediatement le fetch idTS.
- Le compteur de requetes MockServer reste a `1` au lieu de passer a `2`.

Preuve E2E:

```text
[Metadata request after TMS error must retry the idTS fetch immediately]
expected: 2
 but was: 1
at IssuerTSCache.java:266
```

Cause probable dans `swiyu-issuer`:

- `TrustStatementCacheService.fetchIdentityTrustStatement` attrape les erreurs de fetch et retourne
  `Optional.empty()`.
- `fetchAllProtectedIssuanceAuthorizationTrustStatements` fait la meme chose pour les piaTS.
- `TrustStatementCacheService` cache ensuite `Optional.empty()` pendant
  `NEGATIVE_CACHE_TTL_SECONDS`, actuellement `30` secondes.
- Une indisponibilite temporaire du TMS devient donc une valeur negative cachee: "pas de trust
  statement disponible" pendant 30 secondes.

Impact:

- Une panne courte ou un timeout TMS peut empecher un wallet de recevoir les Trust Statements TP2 dans
  les metadonnees issuer pendant la duree du negative cache.
- Le systeme ne recupere pas immediatement meme si le TMS est redevenu disponible a la requete
  suivante.
- Cela peut provoquer une degradation observable cote wallet: metadata sans idTS/piaTS alors que les
  statements existent deja.

### Bug 2: un piaTS valide mais avec un VCT different invalide le cache idTS/piaTS

Statut: bug produit probable, confirme par E2E.

Test E2E:

```text
IssuerTSCache#tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache
```

Comportement attendu:

- Le TMS retourne un idTS valide.
- Le TMS retourne aussi un piaTS valide, mais son claim `can_issue.vct` ne correspond pas au VCT de la
  credential configuration protegee exposee par l'issuer.
- Ce cas doit etre traite comme un simple "no authorization match" pour cette configuration.
- L'issuer doit injecter l'idTS, ne pas injecter le piaTS non correspondant, et conserver le cache idTS
  et piaTS jusqu'a expiration normale.
- Une requete metadata immediate suivante ne doit pas rappeler le TMS.

Comportement observe:

- La premiere reponse metadata contient bien l'idTS et omet le piaTS non correspondant.
- Mais la requete metadata suivante rappelle le endpoint idTS du TMS.
- Le compteur de requetes idTS passe de `1` a `2`, ce qui montre que le cache idTS a ete invalide.

Preuve E2E:

```text
[No matching piaTS must not trigger another idTS fetch]
expected: 1
 but was: 2
at IssuerTSCache.java:339
```

Cause probable dans `swiyu-issuer`:

- `TrustStatementInjectionService.findMatchingPiaTsForVct` retourne `null` quand aucun piaTS ne
  correspond au VCT de la configuration.
- `injectPiaTsIntoConfig` passe quand meme cette valeur `null` a `verifySignatureOrInvalidate`.
- Le vrai `TrustStatementValidator.validateSignature(null)` rejette la valeur nulle avec une
  `JwtValidatorException`.
- `verifySignatureOrInvalidate` interprete cette exception comme un echec de signature et appelle
  `invalidateAllTrustStatements`, ce qui invalide a la fois le cache idTS et le cache piaTS.

Impact:

- Un piaTS valide pour un autre VCT peut provoquer une invalidation de cache inutile.
- Le bug augmente les appels au TMS et peut masquer la difference entre "aucun piaTS ne correspond a
  ce VCT" et "le statement est cryptographiquement invalide".
- Le comportement est incorrect du point de vue TP2: une autorisation pour un autre VCT ne devrait pas
  etre traitee comme une signature invalide.

### Synthese francaise

Deux bugs issuer sont confirmes par E2E:

1. Une erreur temporaire TMS est cachee negativement pendant 30 secondes, ce qui empeche un retry
   immediat.
2. Un piaTS valide mais non correspondant au VCT invalide les caches idTS/piaTS au lieu d'etre ignore
   proprement pour la configuration concernee.

Dans les deux cas, le probleme est observe via les metadonnees OID4VCI exposees au wallet et les
compteurs de requetes TMS MockServer.

## English

### Context

This report covers issuer-side TP2 bugs around Trust Statement injection into OID4VCI issuer metadata.
The E2E tests are implemented in
`test-wallet-application/src/test/java/ch/admin/bj/swiyu/swiyu_test_wallet/issuer/IssuerTSCache.java`.

### Bug 1: temporary TMS fetch errors are negative-cached

Status: likely product bug, confirmed by E2E.

E2E test:

```text
IssuerTSCache#tenantIssuerMetadata_whenTrustStatementFetchFails_thenNextRequestRetriesImmediately
```

Expected behavior: after a temporary TMS error such as HTTP `503`, the next issuer metadata request
retries the TMS immediately and injects valid idTS/piaTS once available.

Observed behavior: the next metadata request does not retry the idTS fetch immediately.

Evidence:

```text
[Metadata request after TMS error must retry the idTS fetch immediately]
expected: 2
 but was: 1
at IssuerTSCache.java:266
```

Likely root cause: `TrustStatementCacheService` converts fetch failures into `Optional.empty()` and
caches that negative value for `NEGATIVE_CACHE_TTL_SECONDS`, currently 30 seconds.

### Bug 2: non-matching piaTS VCT invalidates trust statement caches

Status: likely product bug, confirmed by E2E.

E2E test:

```text
IssuerTSCache#tenantIssuerMetadata_whenPiaTsVctDoesNotMatch_thenDoesNotInvalidateTrustStatementCache
```

Expected behavior: a valid piaTS for a different `can_issue.vct` should simply not be injected for the
protected credential configuration. It must not invalidate idTS or piaTS caches.

Observed behavior: after a non-matching piaTS VCT, the next metadata request fetches idTS again.

Evidence:

```text
[No matching piaTS must not trigger another idTS fetch]
expected: 1
 but was: 2
at IssuerTSCache.java:339
```

Likely root cause: `TrustStatementInjectionService` passes a null `matchingPiaTs` into signature
validation. The validator rejects it, and the catch path invalidates all trust statement caches.

### English Summary

Two issuer bugs are confirmed by E2E evidence:

1. Temporary TMS fetch failures are negative-cached, preventing immediate retry.
2. A valid piaTS for a different VCT invalidates trust statement caches instead of being skipped.

Both issues are visible at the wallet-facing issuer metadata boundary and are supported by MockServer
TMS request-count assertions.
