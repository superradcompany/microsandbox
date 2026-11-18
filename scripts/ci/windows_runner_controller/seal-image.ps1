param(
    [Parameter(Mandatory)][ValidateSet('win10', 'win11')][string]$Platform,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Revision
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Run only on a dedicated image builder, after bootstrap, reboot, and prepare.
# Never turn a machine that has accepted a CI job into a trusted base image.
$service = Get-CimInstance Win32_Service -Filter "Name='WindowsCiRunner'"
if (-not $service -or $service.State -ne 'Stopped' -or $service.StartMode -ne 'Manual') {
    throw 'Image builder runner service must remain stopped and manual'
}
if (Get-Process -Name Runner.Listener,Runner.Worker -ErrorAction SilentlyContinue) {
    throw 'Image builder has an active runner process'
}
foreach ($name in @('.runner', '.credentials', '.credentials_rsaparams', 'jit.config', '_work', '_diag')) {
    if (Test-Path -LiteralPath (Join-Path 'C:\ci-runner' $name)) { throw 'Image builder contains runner state' }
}
foreach ($feature in @('Microsoft-Hyper-V-All', 'HypervisorPlatform')) {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -ne 'Enabled') {
        throw 'Image builder has not completed virtualization setup'
    }
}
if (-not (Test-Path 'C:\ci-service\RunnerLauncher.exe') -or
    -not (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe')) { throw 'Image builder is incomplete' }

# Each clone receives a new administrator password from Azure and generates
# new SSH host keys during prepare. No operator access or JIT data is captured.
Stop-Service sshd
Set-Service sshd -StartupType Manual
Get-NetFirewallRule -Name WindowsCiSsh -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Remove-Item C:\ProgramData\ssh\ssh_host_* -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\ssh\administrators_authorized_keys -Force -ErrorAction SilentlyContinue
if ((Test-Path C:\ProgramData\ssh\ssh_host_*) -or
    (Test-Path C:\ProgramData\ssh\administrators_authorized_keys)) {
    throw 'Image builder SSH keys could not be removed'
}
Get-ChildItem C:\ci-private -Force | Remove-Item -Force -Recurse
New-Item -ItemType Directory -Force -Path C:\ci-image | Out-Null
Set-Acl -LiteralPath C:\ci-image -AclObject (Get-Acl C:\ci-private)
$manifest = @{
    schema = 1
    platform = $Platform
    revision = $Revision
    build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    preparedAt = [DateTime]::UtcNow.ToString('o')
}
$manifest | ConvertTo-Json | Set-Content C:\ci-image\manifest.json -Encoding Ascii

# Azure generalized Windows images need the DVD driver during first boot.
# The operator removes managed Run Commands before invoking Sysprep separately.
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\cdrom -Name Start -Value 1
Write-Output 'Image sealed without runner credentials or SSH host keys; ready for Sysprep'
