# Loads avulse.sys as a kernel service and runs the test program against it; then runs the
# Windows backend's tests, which install and start the service themselves; and checks that no
# crash dump was written. Run after build.ps1, with test signing on:
#   vagrant winrm windows -e -c "C:\avulse\drivers\windows\scripts\test.ps1"

$ErrorActionPreference = "Stop"
# Pick up the PATH and variables the toolchain script set (cargo, for the backend's tests).
foreach ($scope in "Machine", "User") {
    foreach ($kv in [Environment]::GetEnvironmentVariables($scope).GetEnumerator()) {
        if ($kv.Key -ne "Path") { Set-Item -Path "env:$($kv.Key)" -Value $kv.Value }
    }
}
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("Path", "User")
$pkg = "C:\build\avulse\drivers\windows\driver\target\release\avulse_package"
$test = "C:\build\avulse\drivers\windows\test\target\release\avulse-driver-test.exe"

if (-not (bcdedit /enum "{current}" | Select-String "testsigning\s+Yes")) {
    throw "test signing is off: run toolchain.ps1, then reboot"
}
certutil -f -addstore Root "$pkg\WDRLocalTestCert.cer" | Out-Null
certutil -f -addstore TrustedPublisher "$pkg\WDRLocalTestCert.cer" | Out-Null
verifier /querysettings | Select-String "avulse" | Out-Host

$start = Get-Date
sc.exe stop avulse 2>&1 | Out-Null
sc.exe delete avulse 2>&1 | Out-Null
Copy-Item "$pkg\avulse.sys" C:\Windows\System32\drivers\avulse.sys -Force
sc.exe create avulse type= kernel start= demand binPath= System32\drivers\avulse.sys | Out-Host
sc.exe start avulse | Out-Host
if ($LASTEXITCODE -ne 0) { throw "the driver did not start: $LASTEXITCODE" }

$failed = $false
try {
    & $test
    if ($LASTEXITCODE -ne 0) { $failed = $true }
} finally {
    # The test leaves a handle open at exit: stopping works only if its cleanup closed it.
    sc.exe stop avulse | Out-Host
    if ($LASTEXITCODE -ne 0) { $failed = $true; Write-Host "the driver did not stop" }
    sc.exe delete avulse | Out-Host
}
# Then the user-mode backend (crates/avulse/tests/capture_windows.rs), which installs and starts
# the service itself from AVULSE_DRIVER, and the service is removed again.
Write-Host "== the Windows backend"
$env:AVULSE_DRIVER = "$pkg\avulse.sys"
Set-Location C:\build\avulse
cargo test -p avulse --test capture_windows -- --test-threads=1
if ($LASTEXITCODE -ne 0) { $failed = $true }
sc.exe stop avulse | Out-Host
sc.exe delete avulse | Out-Host

if (Get-ChildItem C:\Windows\Minidump, C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -gt $start) {
    throw "a crash dump was written during the test"
}
if ($failed) { throw "the test program failed" }
Write-Host "== passed"
