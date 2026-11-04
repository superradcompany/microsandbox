param([Parameter(Mandatory)][string]$PublicKey, [Parameter(Mandatory)][string]$SshSource)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
if ($PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?$') { throw 'Invalid public key' }
if ($SshSource -notmatch '^\d{1,3}(\.\d{1,3}){3}/32$') { throw 'SSH requires a single client address' }
$private='C:\ci-private'
$runner='C:\ci-runner'
New-Item -ItemType Directory -Force -Path $private,$runner | Out-Null
# New directories can carry explicit broad grants on some Windows images.
# Removing inheritance alone does not remove those grants. Replace the ACL
# only on our own directory, never on Windows or Azure agent directories.
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $private -AclObject $acl

function Download-Verified([string]$Url,[string]$File,[string]$Hash) {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $File
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash -ne $Hash) { throw 'Installer checksum mismatch' }
}

# Job hosts need no compiler, developer credential, or repository checkout.
Download-Verified 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/PowerShell-7.6.9-win-x64.msi' "$private\pwsh.msi" '50d33c7494aaf82b987cfd4de3f232d04f91fdd4c0deeca8a669cced3e7cf8f9'
$p=Start-Process msiexec.exe -ArgumentList '/i',"$private\pwsh.msi",'/qn','/norestart','ADD_PATH=1' -Wait -PassThru
if ($p.ExitCode -notin @(0,3010)) { throw 'PowerShell installation failed' }
Download-Verified 'https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-win-x64-2.338.2.zip' "$private\runner.zip" 'a1f17aa987fc8158bc7521d284912267a0d01b7c2c4684b33c86783b5e8221cc'
Expand-Archive -LiteralPath "$private\runner.zip" -DestinationPath $runner -Force

# Use the same verified OpenSSH build on both Windows versions. The inbox
# Windows 10 build can depend on an unavailable API on older client images.
Download-Verified 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip' "$private\openssh.zip" 'b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957'
Expand-Archive -LiteralPath "$private\openssh.zip" -DestinationPath 'C:\Program Files' -Force
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1' *> "$private\openssh-install.log"
if ($LASTEXITCODE -ne 0) { throw 'OpenSSH installation failed' }
New-Item -ItemType Directory -Force -Path C:\ProgramData\ssh | Out-Null
[IO.File]::WriteAllText('C:\ProgramData\ssh\administrators_authorized_keys',$PublicKey.Trim()+"`n",[Text.UTF8Encoding]::new($false))
@'
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers ciadmin
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
Subsystem sftp sftp-server.exe
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
'@ | Set-Content C:\ProgramData\ssh\sshd_config -Encoding Ascii
& icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH key ACL failed' }
# A fresh Marketplace image has no SSH host keys. Generate them before sshd's
# configuration check; first service startup would otherwise be too late.
& 'C:\Program Files\OpenSSH-Win64\ssh-keygen.exe' -A *> "$private\ssh-hostkeys.log"
if ($LASTEXITCODE -ne 0) { throw 'SSH host-key generation failed' }
& 'C:\Program Files\OpenSSH-Win64\sshd.exe' -t
if ($LASTEXITCODE -ne 0) { throw 'SSH configuration failed validation' }
Get-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue | Disable-NetFirewallRule
New-NetFirewallRule -Name WindowsCiSsh -DisplayName 'Windows CI SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Program 'C:\Program Files\OpenSSH-Win64\sshd.exe' -Profile Any -RemoteAddress $SshSource -Action Allow | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart | Out-Null
& bcdedit.exe /set hypervisorlaunchtype auto | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Hypervisor boot configuration failed' }
Write-Output 'Bootstrap complete; restart required'
