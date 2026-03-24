#!/bin/bash
set -euo pipefail

echo "==> Initializing SoftHSM2 tokens..."

export LD_LIBRARY_PATH="/usr/lib/softhsm:/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

: "${HSM_TOKEN_DIR:=/tmp/softhsm-tokens}"
: "${HSM_LIBRARY:=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}"
: "${HSM_LABEL:=issuer-token}"
: "${HSM_KEY_ID:=01}"
: "${HSM_USER_PIN:=1234}"
: "${HSM_SO_PIN:=1234}"
: "${HSM_SIGNING_ALGORITHM:=ES256}"
: "${HSM_CONFIG_PATH:=/tmp/pkcs11.cfg}"

KEYS_DIR="/opt/hsm-keys"


echo "==> Creating token: ${HSM_KEY_ID}"
/usr/local/bin/softhsm2-util --init-token --free \
    --label "${HSM_KEY_ID}" \
    --pin "${HSM_USER_PIN}" \
    --so-pin "${HSM_SO_PIN}"

# GROUPNAME="secp521r1"
# SIGALG="SHA512withECDSA"
GROUPNAME="secp256r1"
SIGALG="SHA256withECDSA"

if ! command -v keytool >/dev/null 2>&1; then
    echo "ERROR: keytool not found in image."
    echo "This issuer needs a certificate-backed PKCS11 entry."
    echo "Use a JDK-based image for tests, or add keytool to the image."
    exit 1
fi

echo "==> Checking if alias already exists in PKCS11 keystore"
if keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -list \
    -alias "${HSM_KEY_ID}" >/dev/null 2>&1; then

    echo "==> Key alias already exists: ${HSM_KEY_ID}"

else
    echo "==> Importing keypair from mounted host files"

    KEYS_DIR="/opt/hsm-keys"

    echo "==> Import private key"
    softhsm2-util \
        --module "${HSM_LIBRARY}" \
        --token "${HSM_KEY_ID}" \
        --label "${HSM_KEY_ID}" \
        --id 01 \
        --import "${KEYS_DIR}/key.pk8.pem" \
        --pin "${HSM_USER_PIN}"

    echo "==> Import certificate"
    pkcs11-tool \
        --module "${HSM_LIBRARY}" \
        --login --pin "${HSM_USER_PIN}" \
        --token-label "${HSM_KEY_ID}" \
        --write-object "${KEYS_DIR}/cert.pem" \
        --type cert \
        --label "${HSM_KEY_ID}" \
        --id 01
fi

echo "==> Checking if alias already exists in PKCS11 keystore"
if keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -list \
    -alias "override-key" >/dev/null 2>&1; then
    echo "==> Key alias already exists: override-key"
else
    echo "==> Generating EC keypair + self-signed cert in PKCS11 token"
    keytool \
        -genkeypair \
        -keystore NONE \
        -storetype PKCS11 \
        -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg "${HSM_CONFIG_PATH}" \
        -storepass "${HSM_USER_PIN}" \
        -alias "override-key" \
        -keyalg EC \
        -groupname "${GROUPNAME}" \
        -sigalg "${SIGALG}" \
        -dname "CN=override-key" \
        -validity 3650
fi

echo "==> keytool entries"
keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -list -v || true

echo "==> pkcs11-tool objects"
/usr/local/bin/pkcs11-tool \
    --module "${HSM_LIBRARY}" \
    --login --pin "${HSM_USER_PIN}" \
    --token-label "${HSM_KEY_ID}" \
    --list-objects || true

echo "==> Exporting public keys to shared volume"
EXPORT_DIR="${HSM_TOKEN_DIR}/exported"
mkdir -p "${EXPORT_DIR}"

echo "==> Exporting public key for alias: ${HSM_KEY_ID}"
/usr/local/bin/pkcs11-tool \
    --module "${HSM_LIBRARY}" \
    --token-label "${HSM_KEY_ID}" \
    --login --pin "${HSM_USER_PIN}" \
    --label "${HSM_KEY_ID}" \
    --type pubkey \
    --read-object \
    -o "${EXPORT_DIR}/assert_key_pub.der" || true

echo "==> Exporting public key for alias: override-key"
/usr/local/bin/pkcs11-tool \
    --module "${HSM_LIBRARY}" \
    --token-label "${HSM_KEY_ID}" \
    --login --pin "${HSM_USER_PIN}" \
    --label "override-key" \
    --type pubkey \
    --read-object \
    -o "${EXPORT_DIR}/auth_key_pub.der" || true

echo "==> Exporting certificates"
keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -exportcert \
    -alias "${HSM_KEY_ID}" \
    -file "${EXPORT_DIR}/assert_key.crt" 2>/dev/null || true

keytool \
    -keystore NONE \
    -storetype PKCS11 \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "${HSM_CONFIG_PATH}" \
    -storepass "${HSM_USER_PIN}" \
    -exportcert \
    -alias "override-key" \
    -file "${EXPORT_DIR}/auth_key.crt" 2>/dev/null || true

echo "==> Exported key files:"
ls -la "${EXPORT_DIR}/" || true
chmod -R 777 "${HSM_TOKEN_DIR}" || true

echo "==> HSM container initialised successfully"

sleep infinity