# pydivert's Windows suite (its scripts/run-tests-windows.ps1's steps) with avulse's DLL and driver
# in place of WinDivert's two files, under their names, under Driver Verifier. In pydivert's own
# windows VM: copy WinDivert64.dll (avulse_windivert.dll), avulse.sys, WDRLocalTestCert.cer and
# this folder's verifier.ps1 and pydivert.ps1 into pydivert's .avulse folder (untracked), then
#   python3 scripts/vm.py up windows
#   python3 scripts/vm.py exec windows 'powershell -Command "bcdedit /set testsigning on; powershell -ExecutionPolicy Bypass -File C:\pydivert\.avulse\verifier.ps1; exit 0"'
#   python3 scripts/vm.py reboot windows
#   python3 scripts/vm.py exec windows "powershell -ExecutionPolicy Bypass -File C:\pydivert\.avulse\pydivert.ps1"
#   python3 scripts/vm.py destroy windows; rm -r .avulse

$Src = "C:\pydivert"; $Dst = "C:\pydivert_test"; $Av = "C:\pydivert\.avulse"
$start = Get-Date
certutil -f -addstore Root "$Av\WDRLocalTestCert.cer" | Out-Null
certutil -f -addstore TrustedPublisher "$Av\WDRLocalTestCert.cer" | Out-Null
verifier /querysettings | Out-Host
if (!(Test-Path $Dst)) { New-Item -ItemType Directory -Force -Path $Dst | Out-Null }
robocopy $Src $Dst /MIR /XD .venv .git .idea .avulse /XF *.json /R:1 /W:1 /NFL /NDL /NJH /NJS
if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }
Set-Location $Dst
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"
# The newest CPython may have no wheels yet for some test dependencies (pyyaml for 3.15).
$env:UV_PYTHON = "3.13"
foreach ($uvPath in @("$env:USERPROFILE\.local\bin", "$env:USERPROFILE\.cargo\bin")) {
    if (Test-Path "$uvPath\uv.exe") {
        $env:Path = "$uvPath;$env:Path"
        break
    }
}
uv sync --extra test
if ($LASTEXITCODE -ne 0) { throw "uv sync failed" }
uv run python scripts/fetch_binaries.py
# A drop-in: avulse's two files under WinDivert's names.
Copy-Item "$Av\WinDivert64.dll" "$Dst\pydivert\windivert_dll\WinDivert64.dll" -Force
Copy-Item "$Av\avulse.sys" "$Dst\pydivert\windivert_dll\WinDivert64.sys" -Force
Get-ChildItem "$Dst\pydivert\windivert_dll" | Format-Table Name, Length | Out-Host
uv run pytest pydivert\tests -p no:cacheprovider -q -rs
$code = $LASTEXITCODE
# The suite leaves the driver loaded: Driver Verifier must be watching it.
$q = verifier /query | Out-String
if ($q -notmatch "(?im)^\s*[^\s:]+:\s*WinDivert64\.sys\s*\([^:)]+:\s*[1-9]") { Write-Host "== Driver Verifier did not watch WinDivert64.sys"; $code = 1 }
Write-Host "== services"
sc.exe query WinDivert | Out-Host
sc.exe qc WinDivert | Select-String BINARY_PATH | Out-Host
sc.exe stop WinDivert | Out-Host
sc.exe delete WinDivert | Out-Host
if (Get-ChildItem C:\Windows\Minidump, C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -gt $start) { Write-Host "== a crash dump was written"; exit 1 }
Write-Host "== pytest exit $code"
exit $code
