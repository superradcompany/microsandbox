param([Parameter(Mandatory)][string]$JitConfig)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$null=[Convert]::FromBase64String($JitConfig)
if ((Get-Service WindowsCiRunner).Status -ne 'Stopped') { throw 'Runner is already active' }
[IO.File]::WriteAllText('C:\ci-runner\jit.config',$JitConfig,[Text.UTF8Encoding]::new($false))
& icacls C:\ci-runner\jit.config /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-20:M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'JIT configuration ACL failed' }
Write-Output 'Single-use configuration staged; runner remains stopped'
