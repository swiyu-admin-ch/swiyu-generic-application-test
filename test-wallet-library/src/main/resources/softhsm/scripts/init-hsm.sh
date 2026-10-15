#!/bin/bash
set -euo pipefail

# Expand dynamic linker search path with softhsm library
export LD_LIBRARY_PATH="/usr/lib/softhsm:/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export EXPORT_DIR="${HSM_TOKEN_DIR}/exported"

# Setup directories
mkdir -p "${EXPORT_DIR}"
ls -la "${EXPORT_DIR}/" || true

# As we might have perms issues with the mounted volume, we set the permissions to allow read/write access for all users.
apply_perms() {
  chmod -R 777 "${HSM_TOKEN_DIR}" || true
}

create_token() {
    local token="$1"

    echo "Creating token: ${token}"
    /usr/local/bin/softhsm2-util \
        --init-token \
        --free \
        --label "${token}" \
        --pin "${HSM_USER_PIN}" \
        --so-pin "${HSM_USER_PIN}"
}

import_key() {
    local token="$1"
    local alias="$2"
    local keystore_file="${KEYS_DIR}${alias}.p12"

    echo "Importing test keypair ${token}:${alias} from ${keystore_file}"

    # Unlike softhsm2-util, this import applies the attributes in HSM_CONFIG_PATH.
    keytool \
        -importkeystore \
        -srckeystore "${keystore_file}" \
        -srcstoretype PKCS12 \
        -srcstorepass changeit \
        -srcalias "${alias}" \
        -destkeystore NONE \
        -deststoretype PKCS11 \
        -deststorepass "${HSM_USER_PIN}" \
        -destalias "${alias}" \
        -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg "${HSM_CONFIG_PATH}" \
        -noprompt
}

export_cert() {
    local alias="$1"
    local outfile="${EXPORT_DIR}/${alias}.crt"

    echo "Exporting certificate for alias: ${alias} -> ${outfile}"

    keytool \
        -keystore NONE \
        -storetype PKCS11 \
        -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg "${HSM_CONFIG_PATH}" \
        -storepass "${HSM_USER_PIN}" \
        -exportcert \
        -rfc \
        -alias "${alias}" \
        -file "${outfile}"
}

ISSUER_TOKEN="issuer-token"

echo "Creating tokens"
create_token "${ISSUER_TOKEN}"

echo "Importing keypair from mounted host files"
import_key "${ISSUER_TOKEN}" "01"
import_key "${ISSUER_TOKEN}" "02"

echo "Exporting certificates with the public keys to the shared volume"
export_cert "01"
export_cert "02"

apply_perms

echo "keytool entries :"
keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -list -v || true

echo "pkcs11-tool objects :"
pkcs11-tool \
    --module "${HSM_LIBRARY}" \
    --login \
    --pin "${HSM_USER_PIN}" \
    --token-label "${ISSUER_TOKEN}" \
    --list-objects || true

echo "HSM container initialised successfully"
