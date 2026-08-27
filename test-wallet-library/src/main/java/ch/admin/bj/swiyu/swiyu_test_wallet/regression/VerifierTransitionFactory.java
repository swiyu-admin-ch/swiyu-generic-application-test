package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import ch.admin.bj.swiyu.swiyu_test_wallet.config.EnvironmentConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.MockServerClientConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.config.VerifierImageConfig;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierRuntimeFactory;
import ch.admin.bj.swiyu.swiyu_test_wallet.environment.VerifierVariant;
import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Objects;
import java.util.UUID;

import static ch.admin.bj.swiyu.swiyu_test_wallet.util.PathSupport.toUri;

/** Assembles a Verifier transition while preserving its logical identity and database schema. */
@Slf4j
final class VerifierTransitionFactory {

    private final RegressionTransitionConfigurationResolver configurationResolver;
    private final RegressionTransitionResourceResolver resourceResolver;
    private final VerifierImageConfig imageTemplate;
    private final VerifierRuntimeFactory runtimeFactory;
    private final PostgreSQLContainer<?> database;

    VerifierTransitionFactory(
            final RegressionTransitionConfigurationResolver configurationResolver,
            final RegressionTransitionResourceResolver resourceResolver,
            final VerifierImageConfig imageTemplate,
            final VerifierRuntimeFactory runtimeFactory,
            final PostgreSQLContainer<?> database) {
        this.configurationResolver = Objects.requireNonNull(configurationResolver, "configurationResolver");
        this.resourceResolver = Objects.requireNonNull(resourceResolver, "resourceResolver");
        this.imageTemplate = Objects.requireNonNull(imageTemplate, "imageTemplate");
        this.runtimeFactory = Objects.requireNonNull(runtimeFactory, "runtimeFactory");
        this.database = Objects.requireNonNull(database, "database");
    }

    VerifierVersionTransition create() {
        final RegressionTransitionConfigurationResolver.ResolvedTransition<VerifierVariant> configured =
                configurationResolver.requireVerifierTransition();
        final RegressionTransitionResourceResolver.ResolvedTransitionResources<VerifierVariant> resources =
                resourceResolver.resolve("verifier", imageTemplate.getBaseImage(), configured);
        final RegressionSchema schema = RegressionSchema.verifier(database);

        final VerifierImageConfig previousImage = configured.previous().variant().imageConfig(imageTemplate);
        final VerifierImageConfig candidateImage = configured.candidate().variant().imageConfig(imageTemplate);
        configureImage(previousImage, configured.previous().version(), schema.surname());
        configureImage(candidateImage, configured.candidate().version(), schema.surname());

        final VerifierConfig logicalConfig = EnvironmentConfig.createVerifierConfig(
                toUri("https://%s/api/v1/did/%s".formatted(
                        MockServerClientConfig.MOCKSERVER_HOST,
                        UUID.randomUUID()
                ))
        );
        logTransition(resources.previous(), resources.candidate(), schema.schemaName());

        return new VerifierVersionTransition(
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
            final VerifierImageConfig image,
            final String version,
            final String schemaSurname) {
        image.setImageTag(version);
        image.setSurname(schemaSurname);
    }

    private static void logTransition(
            final VersionedComponent<VerifierVariant> previous,
            final VersionedComponent<VerifierVariant> candidate,
            final String schema) {
        log.info(
                "Verifier regression transition: Previous {} [{}; {}] -> Candidate {} [{}; {}], "
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
