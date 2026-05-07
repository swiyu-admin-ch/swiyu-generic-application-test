package ch.admin.bj.swiyu.tsbuilder;

import java.time.Instant;

public final class Tp2BuilderAccess {

    private Tp2BuilderAccess() {
    }

    public static IdTsBuilder identity(IdTsBuilder builder, String kid, String subject,
                                       Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withSubject(subject)
                .withValidity(issuedAt, expiresAt);
    }

    public static VqPsBuilder verificationQueryPublic(VqPsBuilder builder, String kid, String subject,
                                                      Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withSubject(subject)
                .withValidity(issuedAt, expiresAt);
    }

    public static PvaTsBuilder protectedVerificationAuthorization(PvaTsBuilder builder, String kid, String subject,
                                                                 Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withSubject(subject)
                .withValidity(issuedAt, expiresAt);
    }

    public static PiaTsBuilder protectedIssuanceAuthorization(PiaTsBuilder builder, String kid, String subject,
                                                             Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withSubject(subject)
                .withValidity(issuedAt, expiresAt);
    }

    public static PiTlsBuilder protectedIssuanceTrustList(PiTlsBuilder builder, String kid,
                                                         Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withValidity(issuedAt, expiresAt);
    }

    public static NcTlsBuilder nonComplianceTrustList(NcTlsBuilder builder, String kid,
                                                     Instant issuedAt, Instant expiresAt) {
        return builder.withKid(kid)
                .withValidity(issuedAt, expiresAt);
    }
}
