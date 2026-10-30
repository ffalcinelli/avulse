"""Registers the approved extension with launchd, as sysextd does when it activates one.

activate.sh approves the extension by editing sysextd's database, which skips that step, and
nesessionmanager finds packet providers through the job's launch event (run 41029887542: "Found
0 registrations"). The job comes from the database entry's staged bundle, with the launch event
of the entry's additionalLaunchdPlistEntries archive; not its MachServices, which the job that
nesessionmanager then makes to run the provider owns (run 41032129926). Run as root:
launchd_job.py <extension identifier>.
"""

import plistlib
import subprocess
import sys

ext = sys.argv[1]
with open("/Library/SystemExtensions/db.plist", "rb") as f:
    db = plistlib.load(f)
entry = next(e for e in db["extensions"] if e["identifier"] == ext)
staged = entry["stagedBundleURL"]["relative"].removeprefix("file://").rstrip("/")
job = {
    "Label": ext,
    "Program": f"{staged}/Contents/MacOS/{ext}",
    "LaunchEvents": {
        "com.apple.networkextension.provider.matching": {
            ext: {
                "NEExtensionPoints": ["com.apple.networkextension.filter-packet"],
                "NEProviderBundleIdentifier": ext,
            }
        }
    },
    "ProcessType": "Interactive",
}
path = f"/Library/LaunchDaemons/{ext}.plist"
with open(path, "wb") as f:
    plistlib.dump(job, f)
print(path, job["Program"])
for cmd in (
    ["launchctl", "bootstrap", "system", path],
    ["launchctl", "kickstart", "-k", "system/com.apple.nesessionmanager"],
):
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(" ".join(cmd), "->", r.returncode, r.stdout.strip(), r.stderr.strip())
