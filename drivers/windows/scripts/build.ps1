# Builds avulse.sys (test-signed, with its INF and catalog) and the test program in the Windows VM,
# for x64 and ARM64, and checks both drivers' images for HVCI (check-image.ps1):
#   vagrant winrm windows -e -c "C:\avulse\drivers\windows\scripts\build.ps1"
# The x64 driver package lands in C:\build\avulse\drivers\windows\driver\target\release\avulse_package,
# the ARM64 one in ...\driver\target\aarch64-pc-windows-msvc\release\avulse_package, the test program
# in C:\build\avulse\drivers\windows\test\target\release. ARM64 is built only: no ARM64 machine runs
# it.

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

$scripts = "C:\build\avulse\drivers\windows\scripts"
Set-Location C:\build\avulse\drivers\windows\driver
cargo clippy --release -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "clippy found problems in the driver" }
cargo wdk build --profile release
if ($LASTEXITCODE -ne 0) { throw "cargo wdk build failed" }
Get-ChildItem target\release\avulse_package | Format-Table Name, Length
& "$scripts\check-image.ps1" target\release\avulse_package\avulse.sys

cargo clippy --release --target aarch64-pc-windows-msvc -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "clippy found problems in the ARM64 driver" }
cargo wdk build --profile release --target-arch arm64
if ($LASTEXITCODE -ne 0) { throw "cargo wdk build failed for ARM64" }
Get-ChildItem target\aarch64-pc-windows-msvc\release\avulse_package | Format-Table Name, Length
& "$scripts\check-image.ps1" target\aarch64-pc-windows-msvc\release\avulse_package\avulse.sys

Set-Location C:\build\avulse\drivers\windows\test
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "building the test program failed" }
cargo build --release --target aarch64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw "building the ARM64 test program failed" }

# The user-mode side for ARM64: the backend and WinDivert.dll.
Set-Location C:\build\avulse
cargo build --release -p avulse -p avulse-windivert-compat --target aarch64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw "building the ARM64 user-mode crates failed" }
