# Installs the spike driver, checks that it blocks DNS (WFP) and counts frames (NDIS), then
# uninstalls it and prints the counters it saved. Run after build.ps1, with test signing on:
#   vagrant winrm windows -e -c "C:\avulse\spikes\windows-driver\scripts\test.ps1"

$ErrorActionPreference = "Stop"
$pkg = "C:\build\avulse\spikes\windows-driver\target\release\avulse_spike_package"

if (-not (bcdedit /enum "{current}" | Select-String "testsigning\s+Yes")) {
    throw "test signing is off: run toolchain.ps1, then reboot"
}
certutil -f -addstore Root "$pkg\WDRLocalTestCert.cer" | Out-Null
certutil -f -addstore TrustedPublisher "$pkg\WDRLocalTestCert.cer" | Out-Null

function Test-Dns {
    Clear-DnsClientCache
    try {
        Resolve-DnsName -Name example.com -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null
        $true
    } catch {
        $false
    }
}

$start = Get-Date
Remove-Item HKLM:\SOFTWARE\AvulseSpike -ErrorAction SilentlyContinue
$before = Test-Dns

Write-Host "== install"
netcfg.exe -v -l "$pkg\avulse_spike.inf" -c s -i avulse_spike
if ($LASTEXITCODE -ne 0) { throw "netcfg install failed: $LASTEXITCODE" }
sc.exe query avulse_spike
Get-NetAdapterBinding -ComponentID avulse_spike | Format-Table Name, Enabled

$during = Test-Dns
# Traffic for the NDIS filter's program (`tcp.port in {80 443} or arp`), without DNS.
for ($i = 0; $i -lt 3; $i++) {
    try { Invoke-WebRequest https://1.1.1.1 -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}
}
# An exact count for the NDIS filter's second program (`icmp.type == 8 and ip.dst == 10.0.2.2`).
$pings = 5
ping.exe -n $pings 10.0.2.2 | Out-Host
Start-Sleep -Seconds 2

Write-Host "== uninstall"
netcfg.exe -v -u avulse_spike
if ($LASTEXITCODE -ne 0) { throw "netcfg uninstall failed: $LASTEXITCODE" }
Start-Sleep -Seconds 2
sc.exe query avulse_spike
$after = Test-Dns

Write-Host "== counters"
$c = Get-ItemProperty HKLM:\SOFTWARE\AvulseSpike
$c | Select-Object Wfp*, Lwf*, Copied, Unreadable, MinStack, Expanded, ExpandFailed | Format-List
Write-Host "DNS before: $before, while loaded: $during, after: $after (expected True, False, True)"
if (-not $before -or $during -or -not $after) { throw "DNS was not blocked only while the driver was loaded" }
if ($c.LwfPing -ne $pings) { throw "the NDIS filter counted $($c.LwfPing) echo requests, not $pings" }
if ($c.WfpBlocked -eq 0 -or $c.LwfAttached -eq 0 -or $c.LwfMatched -eq 0) { throw "a hook saw nothing" }
if ($c.Unreadable -ne 0 -or $c.ExpandFailed -ne 0) { throw "some packets were not evaluated" }
if (Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt $start) {
    throw "a crash dump was written during the test"
}
Write-Host "== passed"
