#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCRIPT_DIR}/../keys"

# Clean existing keys
echo "Cleaning existing keys in ${BASE_DIR}"
rm -rf "${BASE_DIR:?}/"*

mkdir -p "${BASE_DIR:?}/"

generate_key() {
    local NAME="$1"
    local OUT_DIR="${BASE_DIR}"

    echo "Generating key material for: ${NAME}"
    mkdir -p "${OUT_DIR}"

    KEY_PEM="${OUT_DIR}/${NAME}-key.pem"
    KEY_PK8="${OUT_DIR}/${NAME}-key.pk8.pem"
    CERT_PEM="${OUT_DIR}/${NAME}-cert.pem"
    KEYSTORE_P12="${OUT_DIR}/${NAME}.p12"

    # Generate EC private key (secp256r1)
    echo "→ Generating EC private key"
    openssl ecparam \
        -name secp256r1 \
        -genkey \
        -noout \
        -out "${KEY_PEM}"

    # Convert to PKCS#8 (required for softhsm import)
    echo "→ Converting to PKCS#8"
    openssl pkcs8 \
        -topk8 \
        -nocrypt \
        -in "${KEY_PEM}" \
        -out "${KEY_PK8}" \
        -outform PEM

    # Generate self-signed certificate
    echo "→ Generating self-signed certificate"
    openssl req \
        -new \
        -x509 \
        -key "${KEY_PEM}" \
        -out "${CERT_PEM}" \
        -days 3650 \
        -subj "/CN=${NAME}"

    # keytool imports through SunPKCS11 so pkcs11.cfg attributes apply to the key.
    # The password protects generated test fixtures only.
    openssl pkcs12 \
        -export \
        -inkey "${KEY_PK8}" \
        -in "${CERT_PEM}" \
        -name "${NAME}" \
        -out "${KEYSTORE_P12}" \
        -passout pass:changeit

    echo "Files generated in: ${OUT_DIR}"
    ls -l "${OUT_DIR}"
}

echo "Starting key generation..."

generate_key "01"
generate_key "02"

echo "All keys generated in: ${BASE_DIR}"
ls -l "${BASE_DIR}"
