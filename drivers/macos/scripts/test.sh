#!/bin/bash
# Runs the extension's XPC service in its test mode, as a launchd daemon (no packet provider: a
# runner cannot run an ad-hoc signed one), then the backend's tests against it, as root:
# backend::macos::tests::extension_*. Needs scripts/build.sh first. Removes the daemon after.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
out=$root/target/macos
label=com.github.ffalcinelli.avulse.test
service=com.github.ffalcinelli.avulse.test
plist=/Library/LaunchDaemons/$label.plist
log=$out/avulse-ext-test.log

sudo python3 - "$plist" "$label" "$out/avulse-ext-test" "$service" "$log" <<'PY'
import plistlib, sys
path, label, program, service, log = sys.argv[1:]
with open(path, "wb") as f:
    plistlib.dump({
        "Label": label,
        "ProgramArguments": [program, "--test", "--service", service],
        "MachServices": {service: True},
        "StandardErrorPath": log,
        "StandardOutPath": log,
    }, f)
PY
cleanup() {
    sudo launchctl bootout "system/$label" 2>/dev/null || true
    sudo rm -f "$plist"
    [ -f "$log" ] && { echo "--- the daemon's log"; cat "$log"; }
}
trap cleanup EXIT
sudo launchctl bootstrap system "$plist"

cd "$root"
bin=$(cargo test -p avulse --lib --no-run 2>&1 | grep -o 'target/debug/deps/avulse-[0-9a-f]*' | head -n 1)
sudo AVULSE_EXTENSION_TEST=1 AVULSE_MACH_SERVICE="$service" "$root/$bin" extension_ \
    --test-threads=1 --nocapture
