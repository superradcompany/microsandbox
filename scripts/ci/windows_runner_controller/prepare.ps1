param(
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$Launcher,
    [ValidateSet('', 'win10', 'win11')][string]$ImagePlatform = '',
    [string]$PublicKey,
    [string]$SshSource
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$private='C:\ci-private'
function Set-CiDirectoryAcl([string]$Path,[string]$JobRights) {
    # Replace explicit image defaults as well as inheritance, but only on
    # directories we created. Never apply this to OS or agent state.
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    if ($JobRights) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-20'),$JobRights,'ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
# Reassert the private boundary after bootstrap installers have completed.
Set-CiDirectoryAcl $private ''
$service = Get-CimInstance Win32_Service -Filter "Name='WindowsCiRunner'"
if ($service -and ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Manual' -or
    $service.StartName -notin @('NT AUTHORITY\NetworkService', 'NT AUTHORITY\NETWORK SERVICE') -or
    $service.PathName.Trim('"') -cne 'C:\ci-service\RunnerLauncher.exe')) {
    throw 'Unexpected runner service state'
}
foreach ($name in @('.runner', '.credentials', '.credentials_rsaparams', 'jit.config', '_work', '_diag')) {
    if (Test-Path -LiteralPath (Join-Path 'C:\ci-runner' $name)) { throw 'Worker is not unused' }
}
if ($ImagePlatform) {
    # Images are captured only from dedicated builders that never register a
    # runner. Validate their contract before giving this new VM any job access.
    $manifest = Get-Content C:\ci-image\manifest.json -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or $manifest.platform -cne $ImagePlatform -or
        $manifest.build -ne (Get-CimInstance Win32_OperatingSystem).BuildNumber) {
        throw 'Prepared image does not match the requested platform'
    }
    foreach ($feature in @('Microsoft-Hyper-V-All', 'HypervisorPlatform')) {
        if ((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -ne 'Enabled') {
            throw 'Prepared image is missing virtualization support'
        }
    }
    if ($PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?$' -or
        $SshSource -notmatch '^\d{1,3}(\.\d{1,3}){3}/32$') { throw 'Invalid worker SSH configuration' }
    Stop-Service sshd -ErrorAction Stop
    # Host keys and operator access belong to the new VM, never the template.
    Remove-Item C:\ProgramData\ssh\ssh_host_* -Force -ErrorAction SilentlyContinue
    if (Test-Path C:\ProgramData\ssh\ssh_host_*) { throw 'Old SSH host keys could not be removed' }
    [IO.File]::WriteAllText('C:\ProgramData\ssh\administrators_authorized_keys',$PublicKey.Trim()+"`n",[Text.UTF8Encoding]::new($false))
    & icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SSH key ACL failed' }
    & 'C:\Program Files\OpenSSH-Win64\ssh-keygen.exe' -A *> "$private\ssh-hostkeys.log"
    if ($LASTEXITCODE -ne 0) { throw 'SSH host-key generation failed' }
    & 'C:\Program Files\OpenSSH-Win64\sshd.exe' -t
    if ($LASTEXITCODE -ne 0) { throw 'SSH configuration failed validation' }
    Get-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    Get-NetFirewallRule -Name WindowsCiSsh -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name WindowsCiSsh -DisplayName 'Windows CI SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Program 'C:\Program Files\OpenSSH-Win64\sshd.exe' -Profile Any -RemoteAddress $SshSource -Action Allow | Out-Null
    Set-Service sshd -StartupType Automatic
    Start-Service sshd
}
[IO.File]::WriteAllBytes("$private\probe.ps1",[Convert]::FromBase64String($Probe))
& "$private\probe.ps1"
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Launcher))
Remove-Item "$private\RunnerLauncher.exe" -Force -ErrorAction SilentlyContinue
Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies System.ServiceProcess -OutputAssembly "$private\RunnerLauncher.exe" -OutputType ConsoleApplication
$group=Get-LocalGroup -SID 'S-1-5-32-578'
if (-not (Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq 'S-1-5-20' })) {
    Add-LocalGroupMember -Group $group -Member 'NT AUTHORITY\NETWORK SERVICE' -ErrorAction Stop
}

# NetworkService can use its own runner directory, but cannot alter the
# administrator's bootstrap, Azure agent state, SSH setup, or other hosts.
Set-CiDirectoryAcl 'C:\ci-runner' 'Modify'
# Keep the service executable outside the job-writable runner directory. A
# read-only file inside a writable parent can still be replaced via the parent.
New-Item -ItemType Directory -Force -Path C:\ci-service | Out-Null
Set-CiDirectoryAcl 'C:\ci-service' 'ReadAndExecute'
Copy-Item "$private\RunnerLauncher.exe" C:\ci-service\RunnerLauncher.exe
foreach ($directory in @('C:\WindowsAzure','C:\Packages')) {
    if (Test-Path $directory) {
        # Preserve the agent's existing SYSTEM/service ACLs. Replacing them or
        # stripping inheritance recursively can break command/status reporting.
        # Deny only the job identity, including future inherited files, then
        # cover existing descendants that have explicit or protected ACLs.
        & icacls $directory /deny '*S-1-5-20:(OI)(CI)F' *> "$private\agent-acl.log"
        if ($LASTEXITCODE -ne 0) { throw 'Agent-state ACL failed' }
        & icacls "$directory\*" /deny '*S-1-5-20:F' /T /C *> "$private\agent-child-acl.log"
        if ($LASTEXITCODE -ne 0) { throw 'Agent-state access denial failed' }
    }
}
if (-not $service) {
    New-Service -Name WindowsCiRunner -BinaryPathName 'C:\ci-service\RunnerLauncher.exe' -StartupType Manual -Credential ([Management.Automation.PSCredential]::new('NT AUTHORITY\NetworkService',[Security.SecureString]::new())) | Out-Null
}
# The control plane clears the protected Run Command before starting this
# service. No listener is running while setup credentials are being staged.
Write-Output 'Worker preflight and service preparation complete'
