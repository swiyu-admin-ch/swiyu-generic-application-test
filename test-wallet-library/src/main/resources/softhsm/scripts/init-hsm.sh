#!/bin/bash
set -euo pipefail

export LD_LIBRARY_PATH="/usr/lib/softhsm:/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export GROUPNAME="secp256r1"
export SIGALG="SHA256withECDSA"
export EXPORT_DIR="${HSM_TOKEN_DIR}/exported"

# Setup directories
mkdir -p "${EXPORT_DIR}"
ls -la "${EXPORT_DIR}/" || true

create_token() {
    local token="$1"

    echo "Creating token: ${token}"
    /usr/local/bin/softhsm2-util \
        --init-token \
        --free \
        --label "${token}" \
        --pin "${HSM_USER_PIN}" \
        --so-pin "${HSM_USER_PIN}"

    # Set permissions for the token directory to allow read/write access for all users
    chmod -R 777 "${HSM_TOKEN_DIR}" || true
}

import_key() {
    local token="$1"
    local alias="$2"
    local key_file="${KEYS_DIR}${alias}-key.pk8.pem"
    local certificate_file="${KEYS_DIR}${alias}-cert.pem"

    echo "Importing keypair from mounted files ${token}:${alias} (key: ${key_file}, cert: ${certificate_file})"

    softhsm2-util \
        --module "${HSM_LIBRARY}" \
        --token "${token}" \
        --label "${alias}" \
        --id "${alias}" \
        --import "${key_file}" \
        --pin "${HSM_USER_PIN}"

    pkcs11-tool \
        --module "${HSM_LIBRARY}" \
        --login \
        --pin "${HSM_USER_PIN}" \
        --token-label "${token}" \
        --write-object "${certificate_file}" \
        --type cert \
        --label "${alias}" \
        --id "${alias}"
}

export_key() {
    local token="$1"
    local alias="$2"
    local outfile="${EXPORT_DIR}/${alias}_key_pub.der"

    echo "Exporting public key for alias: ${alias} -> ${outfile}"
    pkcs11-tool \
        --module "${HSM_LIBRARY}" \
        --token-label "${token}" \
        --login \
        --pin "${HSM_USER_PIN}" \
        --label "${alias}" \
        --type pubkey \
        --read-object \
        -o "${outfile}" || true
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
        -alias "${alias}" \
        -file "${outfile}" 2>/dev/null || true
}

ISSUER_TOKEN="issuer-token"

echo "Creating tokens"
create_token "${ISSUER_TOKEN}"

echo "Importing keypair from mounted host files"
import_key "${ISSUER_TOKEN}" "01"
import_key "${ISSUER_TOKEN}" "02"

echo "Exporting public keys to shared volume"
export_key "${ISSUER_TOKEN}" "01"
export_key "${ISSUER_TOKEN}" "02"

echo "Exporting certificates"
export_cert "01"
export_cert "02"

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

sleep infinity