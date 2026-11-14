# Exercise the installer functions with offline GitHub responses. Parse the real
# script so tests cannot accidentally run installation or contact the network.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$path = Join-Path $PSScriptRoot '../install.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$GitHubRepo = 'superradcompany/microsandbox'
$LatestReleaseApiUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"
$global:MsbInstallerFixture = @{}
$global:MsbInstallerFixture.Calls = 0
$global:MsbInstallerFixture.Releases = @()
$global:MsbInstallerFixture.ApiFailure = $false
function Invoke-RestMethod {
    param($Uri, $Headers)
    $global:MsbInstallerFixture.Calls++
    if ($global:MsbInstallerFixture.ApiFailure) { throw 'injected API failure' }
    if ($Uri -eq $LatestReleaseApiUrl) { return @{ tag_name = 'v0.7.14' } }
    if ($Uri -notmatch '^https://api.github.com/repos/superradcompany/microsandbox/releases\?per_page=100&page=([0-9]+)$') {
        throw "Unexpected URL: $Uri"
    }
    $offset = ([int]$Matches[1] - 1) * 100
    # Preserve arrays, including empty and single-entry API responses.
    return ,@($global:MsbInstallerFixture.Releases | Select-Object -Skip $offset -First 100)
}
function Release($Tag, $Draft = $false, $Prerelease = $true) {
    return @{ tag_name = $Tag; draft = $Draft; prerelease = $Prerelease }
}
function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected '$Expected', got '$Actual'" }
}
function Assert-Fails($Body, $Message) {
    try { & $Body } catch {
        if ($_.Exception.Message -notlike "*$Message*") { throw }
        return
    }
    throw "Expected failure: $Message"
}
$Channel = ''; $Version = ''
Assert-Equal (Resolve-Version) 'v0.7.14'
$Channel = 'stable'
Assert-Equal (Resolve-Version) 'v0.7.14'
$Channel = ''
foreach ($value in @('0.8.0-rc.1', 'v0.8.0-rc.1')) {
    $Version = $value; $global:MsbInstallerFixture.Calls = 0
    Assert-Equal (Resolve-Version) 'v0.8.0-rc.1'
    Assert-Equal $global:MsbInstallerFixture.Calls 0
}
foreach ($value in @('0.8.0-rc.01', '01.2.3', '../../evil', "0.8.0`n")) {
    $Version = $value
    Assert-Fails { Resolve-Version } 'Invalid release version'
}
$Version = ''; $Channel = 'nightly'
Assert-Fails { Resolve-Version } 'Channel must be'
$Version = '0.8.0-rc.1'; $Channel = 'rc'
Assert-Fails { Resolve-Version } 'not both'
$Version = ''
$global:MsbInstallerFixture.Releases = @((Release 'v0.8.0-rc.9'), (Release 'v0.8.0-rc.10'),
    (Release 'v0.9.0-rc.1' $true), (Release 'v0.9.0-beta.1'),
    (Release 'v0.7.14' $false $false), (Release 'v0.8.0-rc.11' $false $false))
Assert-Equal (Resolve-Version) 'v0.8.0-rc.10'
$global:MsbInstallerFixture.Releases = @((Release 'v0.8.0-rc.1')) * 100 + @((Release 'v0.10.0-rc.1'), (Release 'v0.9.0-rc.20'))
$global:MsbInstallerFixture.Calls = 0
Assert-Equal (Resolve-Version) 'v0.10.0-rc.1'
Assert-Equal $global:MsbInstallerFixture.Calls 2
$global:MsbInstallerFixture.Releases = @((Release 'v0.8.0-rc.1')) * 100 + @((Release 'v0.8.0' $false $false))
Assert-Fails { Resolve-Version } 'No active RC'
$global:MsbInstallerFixture.Releases = @()
Assert-Fails { Resolve-Version } 'No active RC'
$global:MsbInstallerFixture.Releases = @(@{ tag_name = 'v0.8.0-rc.1'; draft = 'false'; prerelease = $true })
Assert-Fails { Resolve-Version } 'Invalid release metadata'
$global:MsbInstallerFixture.ApiFailure = $true
Assert-Fails { Resolve-Version } 'injected API failure'
Write-Host 'PowerShell installer selection checks passed.'

# Run the complete script with inert local ZIP payloads, intercepting every
# HTTP request. Keep user PATH and doctor execution disabled for the fixture.
$global:MsbInstallerFixture.ApiFailure = $false
$global:MsbInstallerFixture.Releases = @((Release 'v0.8.0-rc.1'))
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('msb-ps-install-test-' + [Guid]::NewGuid().ToString('N'))
$fixturePayload = Join-Path $fixtureRoot 'payload'
New-Item -ItemType Directory -Path $fixturePayload -Force | Out-Null
$originalEnvironment = @{}
foreach ($name in @('MSB_HOME', 'MSB_INSTALL_CHANNEL', 'MSB_INSTALL_VERSION', 'MSB_INSTALL_BASE_URL', 'MSB_INSTALL_NO_PATH', 'MSB_INSTALL_NO_DOCTOR')) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $null)
}
try {
    $env:MSB_HOME = Join-Path $fixtureRoot 'installed'
    $env:MSB_INSTALL_NO_PATH = '1'
    $env:MSB_INSTALL_NO_DOCTOR = '1'
    [IO.File]::WriteAllText((Join-Path $fixturePayload 'msb.exe'), 'inert binary')
    [IO.File]::WriteAllText((Join-Path $fixturePayload 'libkrunfw.dll'), 'inert library')
    $global:MsbInstallerFixture.FixtureZip = Join-Path $fixtureRoot 'bundle.zip'
    Compress-Archive -Path (Join-Path $fixturePayload '*') -DestinationPath $global:MsbInstallerFixture.FixtureZip
    $global:MsbInstallerFixture.ExpectedTag = 'v0.8.0-rc.1'
    $global:MsbInstallerFixture.BadChecksum = $false
    $global:MsbInstallerFixture.MissingBundle = $false
    function Invoke-WebRequest {
        param($Uri, $OutFile, $Headers)
        $prefix = "https://github.com/superradcompany/microsandbox/releases/download/$($global:MsbInstallerFixture.ExpectedTag)/"
        if (-not $Uri.StartsWith($prefix)) { throw "Unexpected download URL: $Uri" }
        $file = $Uri.Substring($prefix.Length)
        if ($file -eq 'checksums.sha256') {
            $hash = if ($global:MsbInstallerFixture.BadChecksum) { '0' * 64 } else { (Get-FileHash $global:MsbInstallerFixture.FixtureZip -Algorithm SHA256).Hash }
            [IO.File]::WriteAllText($OutFile, "$hash  microsandbox-windows-aarch64.zip`n$hash  microsandbox-windows-x86_64.zip`n")
        } elseif ($file -in @('microsandbox-windows-aarch64.zip', 'microsandbox-windows-x86_64.zip')) {
            if ($global:MsbInstallerFixture.MissingBundle) { throw 'missing platform bundle' }
            Copy-Item $global:MsbInstallerFixture.FixtureZip $OutFile
        } else { throw "Unexpected asset: $file" }
    }
    & $path -Channel rc
    $installed = Join-Path $env:MSB_HOME 'bin/msb.exe'
    $installedLibrary = Join-Path $env:MSB_HOME 'lib/libkrunfw.dll'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'inert binary'
    Assert-Equal ([IO.File]::ReadAllText($installedLibrary)) 'inert library'
    $global:MsbInstallerFixture.BadChecksum = $true
    Assert-Fails { & $path -Version '0.8.0-rc.1' } 'checksum verification failed'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'inert binary'
    Assert-Equal ([IO.File]::ReadAllText($installedLibrary)) 'inert library'
    $global:MsbInstallerFixture.MissingBundle = $true
    Assert-Fails { & $path -Channel rc } 'missing platform bundle'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'inert binary'
    Assert-Equal ([IO.File]::ReadAllText($installedLibrary)) 'inert library'
    $global:MsbInstallerFixture.BadChecksum = $false
    $global:MsbInstallerFixture.MissingBundle = $false
    $global:MsbInstallerFixture.ExpectedTag = 'v0.7.14'
    $env:MSB_HOME = Join-Path $fixtureRoot 'stable'
    & $path
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $env:MSB_HOME 'bin/msb.exe'))) 'inert binary'
    $env:MSB_HOME = Join-Path $fixtureRoot 'pinned'
    $env:MSB_INSTALL_VERSION = '0.8.0-rc.1'
    $global:MsbInstallerFixture.ExpectedTag = 'v0.8.0-rc.1'
    & $path
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $env:MSB_HOME 'bin/msb.exe'))) 'inert binary'
    Write-Host 'PowerShell offline installation and failure-preservation checks passed.'
} finally {
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name])
    }
    Remove-Item $fixtureRoot -Recurse -Force
}
