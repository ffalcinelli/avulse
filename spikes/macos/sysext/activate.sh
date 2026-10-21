#!/bin/bash
# Copies each bundle that build.sh made to /Applications, runs its app (self-test, then the
# activation request), and appends what happened to the report as JSON lines.
set -uo pipefail
report=$1
out=$(cd "$(dirname "$0")/.." && pwd)/target/sysext
emit() { # name, ok (true/false/null), value
    python3 -c 'import json,sys; print(json.dumps({"probe":"sysext","name":sys.argv[1],"ok":json.loads(sys.argv[2]),"value":sys.argv[3]}))' \
        "$1" "$2" "$3" | tee -a "$report"
}
for variant in AvulseSpike AvulseSpikePlain; do
    sudo rm -rf "/Applications/$variant.app"
    sudo cp -R "$out/$variant.app" /Applications/
    start=$(date '+%Y-%m-%d %H:%M:%S')
    output=$(timeout 60 "/Applications/$variant.app/Contents/MacOS/AvulseSpike" 2>&1)
    status=$?
    ok=false
    grep -q 'SELFTEST ok' <<<"$output" && ok=true
    emit "$variant.run" "$ok" "exit $status
$output"
    logs=$(log show --start "$start" --style compact \
        --predicate 'process == "sysextd" OR process == "amfid" OR subsystem == "com.apple.sx" OR eventMessage CONTAINS "AvulseSpike"' \
        2>&1 | tail -n 40)
    emit "$variant.log" null "$logs"
done
emit systemextensionsctl null "$(systemextensionsctl list 2>&1)"
