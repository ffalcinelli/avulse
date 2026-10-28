# Builds avulse.sys (test-signed, with its INF and catalog) and the test program in the Windows VM:
#   vagrant winrm windows -e -c "C:\avulse\drivers\windows\scripts\build.ps1"
# The driver package lands in C:\build\avulse\drivers\windows\driver\target\release\avulse_package,
# the test program in C:\build\avulse\drivers\windows\test\target\release.

$ErrorActionPreference = "Stop"
# Pick up the PATH and variables the toolchain script set, in case this session predates them.
foreach ($scope in "Machine", "User") {
    foreach ($kv in [Environment]::GetEnvironmentVariables($scope).GetEnumerator()) {
        if ($kv.Key -ne "Path") { Set-Item -Path "env:$($kv.Key)" -Value $kv.Value }
    }
}
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("Path", "User")

# Build from a local copy: VirtualBox shared folders are slow and do not lock files properly.
robocopy C:\avulse C:\build\avulse /MIR /XD target .git .vagrant fuzz book site /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }
# wdk-build finds the top-level manifest from OUT_DIR, so the target directory must stay the
# default one (no CARGO_TARGET_DIR). robocopy's /XD keeps it across runs.
Remove-Item env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue

Set-Location C:\build\avulse\drivers\windows\driver
cargo clippy --release -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "clippy found problems in the driver" }
cargo wdk build --profile release
if ($LASTEXITCODE -ne 0) { throw "cargo wdk build failed" }
Get-ChildItem target\release\avulse_package | Format-Table Name, Length

Set-Location C:\build\avulse\drivers\windows\test
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "building the test program failed" }
