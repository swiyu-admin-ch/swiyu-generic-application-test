package ch.admin.bj.swiyu.swiyu_test_wallet.regression;

import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Owns the unique schema identity allocated to one transition and removes only that schema.
 *
 * <p>The schema is created and migrated by the component at startup; this type does not create it. Removal is
 * idempotent and guarded by a strict name check before executing {@code DROP SCHEMA ... CASCADE}.
 */
final class RegressionSchema {

    private static final Pattern SAFE_NAME = Pattern.compile("[a-z0-9_]+");

    private final PostgreSQLContainer<?> database;
    private final String componentPrefix;
    private final String schemaSurname;
    private final String ownedSchemaName;
    private boolean removed;

    private RegressionSchema(
            final PostgreSQLContainer<?> database,
            final String componentPrefix,
            final String surname,
            final String schemaName) {
        this.database = database;
        this.componentPrefix = componentPrefix;
        this.schemaSurname = surname;
        this.ownedSchemaName = schemaName;
    }

    static RegressionSchema issuer(final PostgreSQLContainer<?> database) {
        return create(database, "swiyu_issuer");
    }

    static RegressionSchema verifier(final PostgreSQLContainer<?> database) {
        return create(database, "swiyu_verifier");
    }

    private static RegressionSchema create(
            final PostgreSQLContainer<?> database,
            final String componentPrefix) {
        final String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        final String surname = "regression_" + suffix;
        return new RegressionSchema(database, componentPrefix, surname, componentPrefix + "_" + surname);
    }

    String surname() {
        return schemaSurname;
    }

    String schemaName() {
        return ownedSchemaName;
    }

    synchronized void remove() {
        if (removed) {
            return;
        }
        validateOwnedSchema();
        try (Connection connection = DriverManager.getConnection(
                database.getJdbcUrl(),
                database.getUsername(),
                database.getPassword());
             Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS \"%s\" CASCADE".formatted(ownedSchemaName));
            removed = true;
        } catch (SQLException exception) {
            throw new IllegalStateException("Cannot remove regression schema " + ownedSchemaName, exception);
        }
    }

    private void validateOwnedSchema() {
        if (!SAFE_NAME.matcher(ownedSchemaName).matches()
                || !ownedSchemaName.startsWith(componentPrefix + "_regression_")) {
            throw new IllegalStateException("Refusing to remove non-regression schema " + ownedSchemaName);
        }
    }
}
