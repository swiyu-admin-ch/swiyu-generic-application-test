package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.IssuerImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.IssuerVariant;
import ch.admin.bj.swiyu.swiyu_test_wallet.issuer.IssuerConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.util.JwtKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Objects;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

/** Assembles an Issuer transition while preserving its logical identity, schema and management authentication key. */
@Slf4j
final class IssuerTransitionFactory {

    private final RegressionTransitionConfigurationResolver configurationResolver;
    private final RegressionTransitionResourceResolver resourceResolver;
    private final IssuerImageConfig imageTemplate;
    private final IssuerRuntimeFactory runtimeFactory;
    private final PostgreSQLContainer<?> database;

    IssuerTransitionFactory(
            final RegressionTransitionConfigurationResolver configurationResolver,
            final RegressionTransitionResourceResolver resourceResolver,
            final IssuerImageConfig imageTemplate,
            final IssuerRuntimeFactory runtimeFactory,
            final PostgreSQLContainer<?> database) {
        this.configurationResolver = Objects.requireNonNull(configurationResolver, "configurationResolver");
        this.resourceResolver = Objects.requireNonNull(resourceResolver, "resourceResolver");
        this.imageTemplate = Objects.requireNonNull(imageTemplate, "imageTemplate");
        this.runtimeFactory = Objects.requireNonNull(runtimeFactory, "runtimeFactory");
        this.database = Objects.requireNonNull(database, "database");
    }

    IssuerVersionTransition create() {
        final RegressionTransitionConfigurationResolver.ResolvedTransition<IssuerVariant> configured =
                configurationResolver.requireIssuerTransition();
        final RegressionTransitionResourceResolver.ResolvedTransitionResources<IssuerVariant> resources =
                resourceResolver.resolve("issuer", imageTemplate.getBaseImage(), configured);
        final RegressionSchema schema = RegressionSchema.issuer(database);

        final IssuerImageConfig previousImage = configured.previous().variant().imageConfig(imageTemplate);
        final IssuerImageConfig candidateImage = configured.candidate().variant().imageConfig(imageTemplate);
        configureImage(previousImage, configured.previous().version(), schema.surname());
        configureImage(candidateImage, configured.candidate().version(), schema.surname());
        shareManagementJwtKey(previousImage, candidateImage);

        final IssuerConfig logicalConfig = EnvironmentConfig.createIssuerConfig(
                toUri("https://%s/api/v1/did/%s".formatted(
                        MockServerClientConfig.MOCKSERVER_HOST,
                        UUID.randomUUID()
                )),
                false,
                null
        );
        logTransition(resources.previous(), resources.candidate(), schema.schemaName());

        return new IssuerVersionTransition(
                resources.previous(),
                resources.candidate(),
                runtimeFactory,
                logicalConfig,
                previousImage,
                candidateImage,
                resources.previousMetadata(),
                resources.candidateMetadata(),
                schema
        );
    }

    private static void configureImage(
            final IssuerImageConfig image,
            final String version,
            final String schemaSurname) {
        image.setImageTag(version);
        image.setSurname(schemaSurname);
    }

    private static void shareManagementJwtKey(
            final IssuerImageConfig previous,
            final IssuerImageConfig candidate) {
        if (!previous.isEnableJwtAuth() && !candidate.isEnableJwtAuth()) {
            return;
        }

        final JwtKeyGenerator sharedGenerator = previous.isEnableJwtAuth()
                ? previous.getJwtKeyGenerator()
                : candidate.getJwtKeyGenerator();
        if (previous.isEnableJwtAuth()) {
            previous.setJwtKeyGenerator(sharedGenerator);
        }
        if (candidate.isEnableJwtAuth()) {
            candidate.setJwtKeyGenerator(sharedGenerator);
        }
    }

    private static void logTransition(
            final VersionedComponent<IssuerVariant> previous,
            final VersionedComponent<IssuerVariant> candidate,
            final String schema) {
        log.info(
                "Issuer regression transition: Previous {} [{}; {}] -> Candidate {} [{}; {}], "
                        + "schema={}, images={} -> {}",
                previous.version(),
                previous.variant(),
                previous.metadata(),
                candidate.version(),
                candidate.variant(),
                candidate.metadata(),
                schema,
                previous.image().imageId(),
                candidate.image().imageId()
        );
    }
}
