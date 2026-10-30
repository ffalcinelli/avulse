# Installs what building a Rust Windows driver needs, without a package manager:
# Visual Studio 2022 Build Tools (MSVC and the Windows 11 SDK 10.0.26100), the WDK 10.0.26100,
# LLVM (libclang, for bindgen), Rust (MSVC host) and cargo-wdk. Then turns on test signing, which
# needs a reboot (`vagrant reload windows`). Safe to run again: installed parts are skipped.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is very slow with the progress bar
$Downloads = "C:\downloads"
New-Item -ItemType Directory -Force -Path $Downloads | Out-Null

function Get-File($url, $out, $sha256) {
    if (Test-Path $out) { return }
    for ($i = 1; $i -le 10; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile "$out.part" -TimeoutSec 1800
            if ($sha256 -and (Get-FileHash "$out.part" -Algorithm SHA256).Hash -ne $sha256) {
                throw "SHA256 mismatch"
            }
            Move-Item "$out.part" $out
            return
        } catch {
            Write-Warning "Download of $url failed (attempt $i): $($_.Exception.Message)"
            Remove-Item "$out.part" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
        }
    }
    throw "Could not download $url"
}

function Install($what, $exe, $arguments) {
    Write-Host "Installing $what..."
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
    # 3010: success, a reboot is needed.
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "$what failed with exit code $($p.ExitCode)"
    }
}

function Add-MachinePath($dir) {
    $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($path -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable("Path", "$path;$dir", "Machine")
    }
    if ($env:Path -notlike "*$dir*") { $env:Path = "$env:Path;$dir" }
}

# MSVC, the Windows SDK, and the Spectre-mitigated libraries drivers link by default, for x64
# and ARM64 (built only: no ARM64 machine runs it).
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasVc = (Test-Path $vswhere) -and
    (& $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath)
if (-not $hasVc) {
    Get-File "https://aka.ms/vs/17/release/vs_buildtools.exe" "$Downloads\vs_buildtools.exe"
    Install "Visual Studio Build Tools" "$Downloads\vs_buildtools.exe" (@(
        "--quiet", "--wait", "--norestart", "--nocache",
        "--add", "Microsoft.VisualStudio.Workload.VCTools",
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "--add", "Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre",
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
        "--add", "Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre",
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.26100"
    ) -join " ")
}

# The WDK, matching the SDK's build number (URL and hash from winget's
# Microsoft.WindowsWDK.10.0.26100 manifest, version 10.1.26100.6584).
$kits = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (-not (Test-Path "$kits\Include\10.0.26100.0\km\ntddk.h")) {
    Get-File "https://download.microsoft.com/download/41fb59c2-1723-45f9-a270-96b73ad58233/KIT_BUNDLE_WDK_MEDIACREATION/wdksetup.exe" `
        "$Downloads\wdksetup.exe" "ED82C46BD98E0F1D07FD6E5075900E42AEDC3FA5E68C06A8764B3DC5303CFF1B"
    Install "the WDK" "$Downloads\wdksetup.exe" "/features + /quiet /norestart /ceip off"
}
Add-MachinePath "$kits\bin\10.0.26100.0\x64"
Add-MachinePath "$kits\bin\10.0.26100.0\x86"
Add-MachinePath "$kits\Tools\10.0.26100.0\x64"

# libclang for bindgen.
if (-not (Test-Path "$env:ProgramFiles\LLVM\bin\libclang.dll")) {
    Get-File "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/LLVM-19.1.7-win64.exe" `
        "$Downloads\llvm.exe"
    Install "LLVM" "$Downloads\llvm.exe" "/S"
}
[Environment]::SetEnvironmentVariable("LIBCLANG_PATH", "$env:ProgramFiles\LLVM\bin", "Machine")
$env:LIBCLANG_PATH = "$env:ProgramFiles\LLVM\bin"

# Rust, for every user (CARGO_HOME and RUSTUP_HOME outside the profile).
$env:CARGO_HOME = "C:\rust\cargo"
$env:RUSTUP_HOME = "C:\rust\rustup"
[Environment]::SetEnvironmentVariable("CARGO_HOME", $env:CARGO_HOME, "Machine")
[Environment]::SetEnvironmentVariable("RUSTUP_HOME", $env:RUSTUP_HOME, "Machine")
Add-MachinePath "C:\rust\cargo\bin"
if (-not (Test-Path "C:\rust\cargo\bin\cargo.exe")) {
    Get-File "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" `
        "$Downloads\rustup-init.exe"
    Install "Rust" "$Downloads\rustup-init.exe" `
        "-y --profile minimal --default-toolchain stable --default-host x86_64-pc-windows-msvc --no-modify-path"
}
# Clippy, which drivers/windows/scripts/build.ps1 runs on the driver, and the ARM64 target.
& C:\rust\cargo\bin\rustup.exe component add clippy rustfmt
& C:\rust\cargo\bin\rustup.exe target add aarch64-pc-windows-msvc
if (-not (Test-Path "C:\rust\cargo\bin\cargo-wdk.exe")) {
    Write-Host "Installing cargo-wdk..."
    & C:\rust\cargo\bin\cargo.exe install cargo-wdk --version 0.1.1 --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo install cargo-wdk failed" }
}

# Test-signed drivers load only with test signing on, after a reboot. Driver Verifier and crash
# dumps are drivers/windows/scripts/verifier.ps1's, the VM's next provisioner.
bcdedit /set testsigning on | Out-Host
Write-Host "Toolchain ready. Reboot (vagrant reload windows) to turn test signing on."
