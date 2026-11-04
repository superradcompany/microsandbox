param([Parameter(Mandatory)][string]$Probe, [Parameter(Mandatory)][string]$Launcher)
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
[IO.File]::WriteAllBytes("$private\probe.ps1",[Convert]::FromBase64String($Probe))
& "$private\probe.ps1"
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Launcher))
Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies System.ServiceProcess -OutputAssembly "$private\RunnerLauncher.exe" -OutputType ConsoleApplication
$group=Get-LocalGroup -SID 'S-1-5-32-578'
Add-LocalGroupMember -Group $group -Member 'NT AUTHORITY\NETWORK SERVICE' -ErrorAction Stop

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
New-Service -Name WindowsCiRunner -BinaryPathName 'C:\ci-service\RunnerLauncher.exe' -StartupType Manual -Credential ([Management.Automation.PSCredential]::new('NT AUTHORITY\NetworkService',[Security.SecureString]::new())) | Out-Null
# The control plane clears the protected Run Command before starting this
# service. No listener is running while setup credentials are being staged.
Write-Output 'Worker preflight and service preparation complete'
