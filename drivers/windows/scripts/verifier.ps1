# Turns on Driver Verifier for avulse's driver under each name it is installed as (avulse.sys,
# WinDivert64.sys for the WinDivert shim, avulse_spike.sys for Spike B), and full kernel memory
# dumps. Both take effect after a reboot. The Vagrantfile runs it when provisioning the windows
# VM; to test the bindings under Verifier, copy it into their VMs and run it there too:
#   powershell -ExecutionPolicy Bypass -File verifier.ps1; then reboot
# test.ps1 checks that these flags are on (Driver Verifier's "Level") before it runs a suite.

$ErrorActionPreference = "Stop"
$Drivers = "avulse.sys", "WinDivert64.sys", "avulse_spike.sys"
# The standard flags (verifier /standard), plus:
#   0x00004000 invariant MDL checking for the driver (WD_RECV chains MDLs to its IRPs),
#   0x00200000 NDIS/WIFI verification (the lightweight filter),
#   0x00800000 kernel synchronization delay fuzzing,
#   0x02000000 code integrity checks (what HVCI requires: no executable pool, no writable code).
$Standard = 0x000209BB
$Flags = $Standard -bor 0x00004000 -bor 0x00200000 -bor 0x00800000 -bor 0x02000000

# verifier exits with a non-zero code when it asks for a reboot: check what it set instead.
verifier /flags ("0x{0:X}" -f $Flags) /driver @Drivers | Out-Host
$settings = verifier /querysettings | Out-String
foreach ($d in $Drivers) {
    if ($settings -notmatch [regex]::Escape($d)) { throw "Driver Verifier does not list $d" }
}
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -Value 2
Write-Host ("Driver Verifier set (flags 0x{0:X}); reboot for it to take effect." -f $Flags)
