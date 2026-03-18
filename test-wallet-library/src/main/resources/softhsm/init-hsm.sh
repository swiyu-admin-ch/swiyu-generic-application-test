#!/bin/bash
set -e

echo "==> Initializing SoftHSM2 tokens..."

# Set LD_LIBRARY_PATH for softhsm libraries
# export LD_LIBRARY_PATH="/usr/local/lib/softhsm/libs:${LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="/usr/lib/softhsm:/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH}"

# Create token directory
mkdir -p "${HSM_TOKEN_DIR}"

# Initialize token if not already done
if ! /usr/local/bin/softhsm2-util --show-slots 2>/dev/null | grep -q "${HSM_LABEL}"; then
    echo "==> Creating token: ${HSM_LABEL}"
    /usr/local/bin/softhsm2-util --init-token --free \
        --label "${HSM_LABEL}" \
        --pin "${HSM_USER_PIN}" \
        --so-pin "${HSM_SO_PIN}"

    # Determine curve based on algorithm
    case "${HSM_SIGNING_ALGORITHM}" in
      ES256) CURVE="prime256v1" ;;
      ES384) CURVE="secp384r1"  ;;
      ES512) CURVE="secp521r1"  ;;
      *)     CURVE="prime256v1" ;;
    esac

    echo "==> Generating key pair (curve=${CURVE})"
     /usr/local/bin/pkcs11-tool \
         --module "${HSM_LIBRARY:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}" \
         --login --pin "${HSM_USER_PIN}" \
         --token-label "${HSM_LABEL}" \
         --keypairgen \
         --key-type "EC:${CURVE}" \
         --label "${HSM_KEY_ID}" \
         --usage-sign

    echo "==> Listing objects"
     /usr/local/bin/pkcs11-tool \
         --module "${HSM_LIBRARY:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}" \
         --login --pin "${HSM_USER_PIN}" \
         --token-label "${HSM_LABEL}" \
         --list-objects

    echo "==> SoftHSM2 initialization completed"
else
    echo "==> Token already initialized"
fi

# exec /app/entrypoint.sh "$@"
exec java -jar /app/app.jar
