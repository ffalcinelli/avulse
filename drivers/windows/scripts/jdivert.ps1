# jdivert's Windows suite with avulse's DLL and driver in place of WinDivert's two files, under
# their names (WinDivert64.dll, WinDivert64.sys), under Driver Verifier. Run with -Jdk 25 (Panama)
# or -Jdk 8 (JNA). In jdivert's own windows VM, as pydivert.ps1 says, with jdivert's .avulse
# folder and C:\jdivert:
#   vagrant winrm windows -e -c 'powershell -ExecutionPolicy Bypass -File C:\jdivert\.avulse\jdivert.ps1 -Jdk 25'

param([string]$Jdk = "25")
$Av = "C:\jdivert\.avulse"; $Dst = "C:\local_jdivert"
$start = Get-Date
certutil -f -addstore Root "$Av\WDRLocalTestCert.cer" | Out-Null
certutil -f -addstore TrustedPublisher "$Av\WDRLocalTestCert.cer" | Out-Null
verifier /querysettings | Out-Host
robocopy C:\jdivert $Dst /MIR /XD .git .vagrant target .local .avulse /R:1 /W:1 /NFL /NDL /NJH /NJS
if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }
Set-Location $Dst
$env:JAVA_HOME = if ($Jdk -eq "8") { "C:\tools\jdk8" } else { "C:\tools\jdk25" }
$env:Path = "C:\tools\maven\bin;$env:JAVA_HOME\bin;" + [Environment]::GetEnvironmentVariable("Path", "Machine")
& "$env:JAVA_HOME\bin\java.exe" -version
mvn -B -q generate-resources
if ($LASTEXITCODE -ne 0) { throw "generate-resources failed" }
# Newer than the downloaded files, so that the build's copy step leaves them.
foreach ($f in @(@("WinDivert64.dll", "WinDivert64.dll"), @("avulse.sys", "WinDivert64.sys"))) {
    $to = "$Dst\target\native-resources\$($f[1])"
    Copy-Item "$Av\$($f[0])" $to -Force
    (Get-Item $to).LastWriteTime = Get-Date
}
Get-ChildItem "$Dst\target\native-resources" | Format-Table Name, Length | Out-Host
mvn -B verify
$code = $LASTEXITCODE
# The jar must carry avulse's files, not WinDivert's.
Write-Host "== native resources: $((Get-Item "$Dst\target\classes\WinDivert64.dll").Length), $((Get-Item "$Dst\target\classes\WinDivert64.sys").Length) bytes"
# The suite leaves the driver loaded: Driver Verifier must be watching it.
$q = verifier /query | Out-String
if ($q -notmatch "(?im)^\s*MODULE:\s*WinDivert64\.sys\s*\(load:\s*[1-9]") { Write-Host "== Driver Verifier did not watch WinDivert64.sys"; $code = 1 }
Write-Host "== services"
sc.exe query WinDivert | Out-Host
sc.exe stop WinDivert | Out-Host
sc.exe delete WinDivert | Out-Host
if (Get-ChildItem C:\Windows\Minidump, C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -gt $start) { Write-Host "== a crash dump was written"; exit 1 }
Write-Host "== mvn exit $code"
exit $code
