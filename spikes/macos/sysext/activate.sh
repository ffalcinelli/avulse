#!/bin/bash
# Installs each bundle that build.sh made in /Applications and runs its app (self-test,
# activation request, then the filter if activation works). While AvulseSpike waits, this tries
# to approve the extension and the filter without anyone at the screen (Step 32):
#   1. the system extension: mark it enabled in sysextd's database (SIP is off), restart sysextd;
#   2. failing that, open its pane in System Settings and dump the UI, for a scripted click;
#   3. the "filter network content" prompt: click any "Allow" button through System Events.
# Enabling the filter needs nehelper's authorization: an ad-hoc signed app is not "entitled", so
# nehelper asks for an authorization right, which the database is set to grant; failing that, the
# app runs again as root.
# Everything that happens goes to the report as JSON lines, with screenshots in target/shots.
set -uo pipefail
report=$1
crate=$(cd "$(dirname "$0")/.." && pwd)
out=$crate/target/sysext
shots=$crate/target/shots
mkdir -p "$shots"
ext=com.github.ffalcinelli.avulse.spike.filter
emit() { # name, ok (true/false/null), value
    python3 -c 'import json,sys; print(json.dumps({"probe":"sysext","name":sys.argv[1],"ok":json.loads(sys.argv[2]),"value":sys.argv[3]}))' \
        "$1" "$2" "$3" | tee -a "$report"
}
# macOS has no timeout(1).
with_timeout() { perl -e 'alarm shift; exec @ARGV' "$@"; }
shot() { with_timeout 20 screencapture -x "$shots/$1.png" 2>&1 || echo "screencapture failed: $?"; }
# Waits up to $2 seconds for the app's output ($3) to contain $1.
wait_for() {
    local i
    for ((i = 0; i < $2; i++)); do
        grep -q "$1" "$3" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
# Clicks the first "Allow" (or "OK") button of any window of any process.
click_allow() {
    with_timeout 60 osascript <<'EOF' 2>&1
tell application "System Events"
    set seen to {}
    repeat with p in (every process)
        try
            repeat with w in (every window of p)
                set end of seen to (name of p) & ": " & (name of w as text)
                repeat with label in {"Allow", "OK"}
                    try
                        click (first button of w whose name is (label as text))
                        return "clicked " & label & " in " & (name of p)
                    end try
                end repeat
            end repeat
        end try
    end repeat
    return "no button; windows: " & (seen as text)
end tell
EOF
}

emit tcc null "$(sudo sqlite3 '/Library/Application Support/com.apple.TCC/TCC.db' \
    "select client, service, auth_value from access where service in ('kTCCServiceAccessibility', 'kTCCServiceAppleEvents', 'kTCCServiceScreenCapture', 'kTCCServicePostEvent')" 2>&1)"
# It may wait for someone to confirm in the GUI: give up after 30 s.
emit developer_mode null "$(with_timeout 30 sudo systemextensionsctl developer on 2>&1; echo "exit $?"; with_timeout 10 systemextensionsctl developer 2>&1)"

rights=$(sudo sqlite3 /var/db/auth.db "select name from rules where name like '%etwork%'" 2>&1)
emit auth_rights null "$rights"
for r in $rights; do
    case $r in
        *networkextension* | *NetworkExtension* | system.preferences.network | system.services.systemconfiguration.network)
            emit "auth_allow $r" null "$(sudo security authorizationdb write "$r" allow 2>&1)" ;;
    esac
done

for variant in AvulseSpike AvulseSpikePlain; do
    sudo rm -rf "/Applications/$variant.app"
    sudo cp -R "$out/$variant.app" /Applications/
    start=$(date '+%Y-%m-%d %H:%M:%S')
    log=$crate/target/$variant.out
    : >"$log"
    "/Applications/$variant.app/Contents/MacOS/AvulseSpike" >"$log" 2>&1 &
    app=$!

    if [ "$variant" = AvulseSpike ] && wait_for 'needs-user-approval' 60 "$log"; then
        shot 1-approval-pending
        emit db_before null "$(sudo plutil -convert xml1 -o - /Library/SystemExtensions/db.plist 2>&1 | head -c 6000)"
        # 1. The database.
        emit db_edit null "$(sudo python3 - "$ext" <<'EOF' 2>&1
import plistlib, sys
path = "/Library/SystemExtensions/db.plist"
with open(path, "rb") as f:
    db = plistlib.load(f)
changed = []
for e in db.get("extensions", []):
    if e.get("identifier") == sys.argv[1]:
        changed.append(e.get("state"))
        e["state"] = "activated_enabled"
with open(path, "wb") as f:
    plistlib.dump(db, f, fmt=plistlib.FMT_BINARY)
print("states before:", changed)
EOF
        sudo launchctl kickstart -k system/com.apple.sysextd 2>&1 || sudo killall -9 sysextd 2>&1; echo "sysextd restarted: $?")"
        sleep 10
        emit after_db_edit null "$(with_timeout 20 systemextensionsctl list 2>&1)"
        # Approved, but not registered with the Network Extension framework: make the launchd
        # job sysextd would have made, if it did not.
        emit launchd_before null "$(sudo launchctl print system 2>&1 | grep -i avulse)"
        if ! sudo launchctl print "system/$ext" >/dev/null 2>&1; then
            emit launchd_job null "$(sudo python3 "$crate/sysext/launchd_job.py" "$ext" 2>&1)"
            emit launchd_after null "$(sudo launchctl print "system/$ext" 2>&1 | head -40)"
        fi
        shot 2-after-db-edit
        # Enabled, but the pending request may never hear of it: a new one completes at once.
        if ! grep -q 'RESULT activated' "$log" &&
            with_timeout 20 systemextensionsctl list 2>&1 | grep -q 'activated enabled'; then
            kill "$app" 2>/dev/null
            wait "$app" 2>/dev/null
            emit first_run null "$(cat "$log")"
            "/Applications/$variant.app/Contents/MacOS/AvulseSpike" >"$log" 2>&1 &
            app=$!
            sleep 10
        fi
        # 2. The UI, if the request is still waiting.
        if ! grep -q 'RESULT activated' "$log"; then
            open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2>&1
            sleep 8
            shot 3-settings
            emit settings_ui null "$(with_timeout 120 osascript -e 'tell application "System Events" to tell process "System Settings" to get entire contents of window 1' 2>&1 | head -c 20000)"
        fi
        # 3. The filter's prompt, once the extension is activated.
        if wait_for 'RESULT activated' 30 "$log"; then
            sleep 5
            shot 4-filter-prompt
            emit click_allow null "$(click_allow)"
            sleep 3
            shot 5-after-click
            wait_for 'RESULT filter' 30 "$log" || emit click_allow_again null "$(click_allow)"
        fi
    fi
    # Let the app finish (the filter run takes about a minute), at most five minutes.
    for ((i = 0; i < 300; i++)); do kill -0 "$app" 2>/dev/null || break; sleep 1; done
    kill "$app" 2>/dev/null
    wait "$app"
    status=$?
    ok=false
    grep -q 'SELFTEST ok' "$log" && ok=true
    emit "$variant.run" "$ok" "exit $status
$(cat "$log")"
    if [ "$variant" = AvulseSpike ] && grep -q 'filter-save failed' "$log"; then
        sudo "/Applications/$variant.app/Contents/MacOS/AvulseSpike" >"$log.root" 2>&1 &
        app=$!
        wait_for 'RESULT filter' 60 "$log.root"
        sleep 3
        shot 6-as-root
        click_allow >/dev/null
        for ((i = 0; i < 300; i++)); do sudo kill -0 "$app" 2>/dev/null || break; sleep 1; done
        sudo kill "$app" 2>/dev/null
        emit "$variant.run_as_root" null "$(cat "$log.root")"
    fi
    if [ "$variant" = AvulseSpike ]; then
        # The provider's own lines, which the general log's tail can cut off.
        emit provider.log null "$(with_timeout 60 log show --start "$start" --style compact --info \
            --predicate 'subsystem == "com.github.ffalcinelli.avulse.spike" OR process CONTAINS "avulse.spike.filter"' \
            2>&1 | head -n 200)"
        emit nesessionmanager.log null "$(with_timeout 60 log show --start "$start" --style compact --info \
            --predicate '(process == "nesessionmanager" OR process == "neagent") AND (eventMessage CONTAINS[c] "filter" OR eventMessage CONTAINS[c] "avulse")' \
            2>&1 | tail -n 120)"
        # Did launchd start it, and did anything kill it (run 41031016569: nesessionmanager
        # sends the start command, and the provider never checks in)?
        staged=$(sudo find /Library/SystemExtensions -name "$ext" -path '*MacOS*' 2>/dev/null | head -1)
        emit staged_binary null "$(sudo ls -le@ "$staged" 2>&1; sudo xattr -l "$staged" 2>&1; \
            sudo codesign -dvvv --entitlements - "$staged" 2>&1 | head -40)"
        emit launchd_job_after null "$(sudo launchctl print "system/$ext" 2>&1 | grep -E 'state|runs|last exit|reason|pid' )"
        emit spawn.log null "$(with_timeout 60 log show --start "$start" --style compact --info \
            --predicate '(process == "kernel" OR process == "launchd" OR process == "amfid" OR process == "syspolicyd") AND (eventMessage CONTAINS[c] "avulse" OR eventMessage CONTAINS "AMFI")' \
            2>&1 | tail -n 80)"
        emit diagnostic_reports null "$(ls -lt /Library/Logs/DiagnosticReports 2>&1 | head -20)"
        emit crashes null "$(ls -l /Library/Logs/DiagnosticReports ~/Library/Logs/DiagnosticReports 2>&1 | grep -i 'avulse' ; \
            for f in /Library/Logs/DiagnosticReports/*avulse* ; do [ -f "$f" ] && head -c 3000 "$f"; done)"
    fi
    emit "$variant.state" null "$(with_timeout 20 systemextensionsctl list 2>&1)"
    logs=$(with_timeout 60 log show --start "$start" --style compact --info \
        --predicate 'process == "sysextd" OR process == "amfid" OR process == "nesessionmanager" OR process == "nehelper" OR subsystem == "com.github.ffalcinelli.avulse.spike" OR eventMessage CONTAINS "AvulseSpike" OR eventMessage CONTAINS "avulse"' \
        2>&1 | tail -n 150)
    emit "$variant.log" null "$logs"
done
