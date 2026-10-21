#!/bin/bash
# Turns on system extension developer mode (it needs SIP off, which the runners have), copies
# each bundle that build.sh made to /Applications, runs its app (self-test, activation request,
# then the filter if activation works), and appends what happened to the report as JSON lines.
set -uo pipefail
report=$1
out=$(cd "$(dirname "$0")/.." && pwd)/target/sysext
emit() { # name, ok (true/false/null), value
    python3 -c 'import json,sys; print(json.dumps({"probe":"sysext","name":sys.argv[1],"ok":json.loads(sys.argv[2]),"value":sys.argv[3]}))' \
        "$1" "$2" "$3" | tee -a "$report"
}
# macOS has no timeout(1).
with_timeout() { perl -e 'alarm shift; exec @ARGV' "$@"; }

emit developer_mode null "$(sudo systemextensionsctl developer on 2>&1; systemextensionsctl developer 2>&1)"
for variant in AvulseSpike AvulseSpikePlain; do
    sudo rm -rf "/Applications/$variant.app"
    sudo cp -R "$out/$variant.app" /Applications/
    start=$(date '+%Y-%m-%d %H:%M:%S')
    output=$(with_timeout 90 "/Applications/$variant.app/Contents/MacOS/AvulseSpike" 2>&1)
    status=$?
    ok=false
    grep -q 'SELFTEST ok' <<<"$output" && ok=true
    emit "$variant.run" "$ok" "exit $status
$output"
    emit "$variant.state" null "$(systemextensionsctl list 2>&1)"
    logs=$(log show --start "$start" --style compact --info \
        --predicate 'process == "sysextd" OR process == "amfid" OR process == "nesessionmanager" OR subsystem == "com.github.ffalcinelli.avulse.spike" OR eventMessage CONTAINS "AvulseSpike" OR eventMessage CONTAINS "avulse"' \
        2>&1 | tail -n 80)
    emit "$variant.log" null "$logs"
done
