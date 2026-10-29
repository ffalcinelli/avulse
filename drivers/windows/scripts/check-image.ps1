# Checks that a driver image meets what memory integrity (HVCI) requires of its layout: sections
# aligned on pages, none both writable and executable, and the image marked NX-compatible.
# Run by build.ps1 and CI on each built avulse.sys:
#   check-image.ps1 path\to\avulse.sys

param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = "Stop"

$b = [IO.File]::ReadAllBytes((Resolve-Path $Path))
$pe = [BitConverter]::ToInt32($b, 0x3C)
if ([BitConverter]::ToUInt32($b, $pe) -ne 0x4550) { throw "$Path is not a PE image" }
$machine = [BitConverter]::ToUInt16($b, $pe + 4)
$sections = [BitConverter]::ToUInt16($b, $pe + 6)
$optSize = [BitConverter]::ToUInt16($b, $pe + 20)
$opt = $pe + 24
$alignment = [BitConverter]::ToUInt32($b, $opt + 32)
$dll = [BitConverter]::ToUInt16($b, $opt + 70)

$problems = @()
if ($alignment % 0x1000 -ne 0) { $problems += "section alignment 0x{0:X} is not a page" -f $alignment }
# IMAGE_DLLCHARACTERISTICS_NX_COMPAT
if (($dll -band 0x100) -eq 0) { $problems += "the image is not marked NX-compatible" }
$rows = for ($i = 0; $i -lt $sections; $i++) {
    $s = $opt + $optSize + 40 * $i
    $name = [Text.Encoding]::ASCII.GetString($b, $s, 8).TrimEnd([char]0)
    $flags = [BitConverter]::ToUInt32($b, $s + 36)
    # IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_MEM_WRITE
    $x = ($flags -band 0x20000000) -ne 0
    $w = ($flags -band 0x80000000) -ne 0
    if ($x -and $w) { $problems += "section $name is writable and executable" }
    [pscustomobject]@{ Section = $name; Flags = "0x{0:X8}" -f $flags; Execute = $x; Write = $w }
}
Write-Host ("{0}: machine 0x{1:X4}, section alignment 0x{2:X}, DllCharacteristics 0x{3:X4}" -f
    $Path, $machine, $alignment, $dll)
$rows | Format-Table | Out-Host
if ($problems) { throw "$Path is not HVCI-compatible: $($problems -join '; ')" }
Write-Host "$Path meets HVCI's image requirements"
