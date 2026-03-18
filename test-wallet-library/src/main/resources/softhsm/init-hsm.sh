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

mkdir -p "${HSM_TOKEN_DIR}"

if ! /usr/local/bin/softhsm2-util --show-slots 2>/dev/null | grep -q "${HSM_LABEL}"; then
    echo "==> Creating token: ${HSM_LABEL}"
    /usr/local/bin/softhsm2-util --init-token --free \
        --label "${HSM_LABEL}" \
        --pin "${HSM_USER_PIN}" \
        --so-pin "${HSM_SO_PIN}"
else
    echo "==> Token already initialized"
fi

case "${HSM_SIGNING_ALGORITHM}" in
  ES256)
    GROUPNAME="secp256r1"
    SIGALG="SHA256withECDSA"
    ;;
  ES384)
    GROUPNAME="secp384r1"
    SIGALG="SHA384withECDSA"
    ;;
  ES512)
    GROUPNAME="secp521r1"
    SIGALG="SHA512withECDSA"
    ;;
  *)
    GROUPNAME="secp256r1"
    SIGALG="SHA256withECDSA"
    ;;
esac

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
    echo "==> Generating EC keypair + self-signed cert in PKCS11 token"
    keytool \
        -genkeypair \
        -keystore NONE \
        -storetype PKCS11 \
        -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg "${HSM_CONFIG_PATH}" \
        -storepass "${HSM_USER_PIN}" \
        -alias "${HSM_KEY_ID}" \
        -keyalg EC \
        -groupname "${GROUPNAME}" \
        -sigalg "${SIGALG}" \
        -dname "CN=${HSM_KEY_ID}" \
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
    --token-label "${HSM_LABEL}" \
    --list-objects || true

echo "==> SoftHSM2 initialization completed"

exec java -jar /app/app.jar