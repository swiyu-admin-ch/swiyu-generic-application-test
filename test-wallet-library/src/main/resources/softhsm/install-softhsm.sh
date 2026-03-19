#!/bin/bash
set -e

echo "==> Setting up SoftHSM2 environment..."

# Copy all .so libraries to system path
echo "==> Copying libraries..."
cp -v /usr/local/lib/softhsm/libs/*.so* /usr/lib/ 2>/dev/null || true

# Set LD_LIBRARY_PATH for softhsm binaries
export LD_LIBRARY_PATH="/usr/local/lib/softhsm/libs:${LD_LIBRARY_PATH}"

echo "==> Verifying SoftHSM2 binaries..."
# Check if binaries exist and are executable
if [ -f /usr/local/bin/softhsm2-util ] && [ -f /usr/local/bin/pkcs11-tool ]; then
    echo "==> SoftHSM2 binaries found"
    # Try to execute softhsm2-util to verify it works
    if /usr/local/bin/softhsm2-util --version 2>&1 | head -1; then
        echo "==> SoftHSM2 binaries are valid"
    else
        echo "==> Warning: Binary validation failed, continuing anyway..."
    fi
else
    echo "==> Error: SoftHSM2 binaries not found!"
    exit 1
fi

echo "==> SoftHSM2 environment ready"

# Now run the init script
exec /usr/local/bin/init-hsm.sh "$@"

