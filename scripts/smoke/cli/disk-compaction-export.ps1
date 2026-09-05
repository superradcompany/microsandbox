$ErrorActionPreference = 'Stop'
$taskRoot = $env:QUAL_ROOT
if (!$taskRoot) { throw 'Set QUAL_ROOT to a dedicated qualification directory containing home/bin/msb.exe and home/lib/libkrunfw-windows.dll' }
$env:MSB_HOME = "$taskRoot\home"
$env:MSB_LIBKRUNFW_PATH = "$taskRoot\home\lib\libkrunfw-windows.dll"
$env:PATH = "$taskRoot\home\lib;$env:PATH"
$bin = "$taskRoot\home\bin\msb.exe"
$output = "$taskRoot\matrix"
New-Item -ItemType Directory -Force "$output\logs" | Out-Null
$names = [Collections.Generic.List[string]]::new()
function Measure-Msb([string]$label, [string[]]$command, [bool]$reject = $false) {
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $ErrorActionPreference = 'Continue'
  & $bin @command 1>"$output\logs\$label.out" 2>"$output\logs\$label.err"
  $exitCode = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  $elapsed = $timer.Elapsed.TotalMilliseconds
  if (($exitCode -eq 0) -eq $reject) {
    "$label`tFAIL`t$elapsed" | Tee-Object -FilePath "$output\results.tsv" -Append
    Get-Content "$output\logs\$label.err"
    throw "$label unexpected exit $exitCode"
  }
  "$label`tPASS`t$elapsed" | Tee-Object -FilePath "$output\results.tsv" -Append
}
try {
 foreach ($layout in @('managed','flat')) {
  $name = "compact-$layout"
  $names.Add($name)
  $spec = if ($layout -eq 'flat') { 'flat:512M' } else { '512M' }
  Measure-Msb "$layout-create" @('create','-n',$name,'--root-disk',$spec,'-m','256M','--max-duration','20m','alpine')
  Measure-Msb "$layout-noop" @('modify',$name,'--compact','--format','json')
  Measure-Msb "$layout-invalid-one" @('modify',$name,'--compact','--layers','1') $true
  Measure-Msb "$layout-invalid-mixed" @('modify',$name,'--compact','--cpus','1') $true
  Measure-Msb "$layout-seed" @('exec',$name,'--','sh','-c','dd if=/dev/urandom of=/payload bs=1048576 count=8 2>/dev/null; sha256sum /payload >/expected; mkdir -p /dev/shm; echo volatile >/dev/shm/ram-marker; sync')
  foreach ($generation in 1..4) {
    Measure-Msb "$layout-write-$generation" @('exec',$name,'--','sh','-c',"echo $generation >/version; sync")
    Measure-Msb "$layout-checkpoint-$generation" @('snapshot','create',"$name-$generation",'--from',$name,'--full')
  }
  Measure-Msb "$layout-dry-run" @('modify',$name,'--compact','--layers','3','--dry-run','--format','json')
  $plan = Get-Content "$output\logs\$layout-dry-run.out" -Raw | ConvertFrom-Json
  if (!$plan.dry_run -or $plan.input_layers -ne 5 -or $plan.output_layers -ne 3) { throw 'invalid dry-run plan' }
  Measure-Msb "$layout-invalid-large" @('modify',$name,'--compact','--layers','99') $true
  Measure-Msb "$layout-save-complete" @('snapshot','save',"$name-4","$output\$layout-complete.tar.zst")
  Measure-Msb "$layout-save-since" @('snapshot','save',"$name-4","$output\$layout-delta.tar.zst",'--since',"$name-2")
  Measure-Msb "$layout-save-last" @('snapshot','save',"$name-4","$output\$layout-last.tar",'--last-layers','2','--plain-tar')
  Measure-Msb "$layout-save-base" @('snapshot','save',"$name-2","$output\$layout-base.tar.zst")
  Measure-Msb "$layout-invalid-last-zero" @('snapshot','save',"$name-4","$output\invalid.tar",'--last-layers','0') $true
  Measure-Msb "$layout-missing-base" @('snapshot','load',"$output\$layout-delta.tar.zst","$output\$layout-missing") $true
  Measure-Msb "$layout-wrong-base" @('snapshot','load',"$output\$layout-delta.tar.zst","$output\$layout-wrong",'--base',"$name-1") $true
  Measure-Msb "$layout-load-delta" @('snapshot','load',"$output\$layout-delta.tar.zst","$output\$layout-import",'--base',"$name-2")
  Measure-Msb "$layout-load-base-archive" @('snapshot','load',"$output\$layout-last.tar","$output\$layout-base-import",'--base',"$output\$layout-base.tar.zst")
  Measure-Msb "$layout-online-compact" @('modify',$name,'--compact','--layers','3','--format','json')
  Measure-Msb "$layout-data-after" @('exec',$name,'--','sh','-c','sha256sum -c /expected && test $(cat /version) = 4 && echo after >/after && sync')
  Measure-Msb "$layout-stop" @('stop',$name)
  Measure-Msb "$layout-offline-compact" @('modify',$name,'--compact','--format','json')
  Measure-Msb "$layout-stopped-snapshot" @('snapshot','create',"$name-stopped",'--from',$name,'--integrity')
  Measure-Msb "$layout-stopped-verify" @('snapshot','verify',"$name-stopped")
  Measure-Msb "$layout-restart" @('start',$name)
  Measure-Msb "$layout-restarted-data" @('exec',$name,'--','sh','-c','sha256sum -c /expected && test $(cat /version) = 4 && test $(cat /after) = after')
  Measure-Msb "$layout-post-compact-checkpoint" @('snapshot','create',"$name-new",'--from',$name,'--full')
  Measure-Msb "$layout-old-prefix-rejected" @('snapshot','save',"$name-new","$output\invalid.tar",'--since',"$name-4") $true
  Measure-Msb "$layout-stop-source" @('stop',$name)
  foreach ($variant in @('old','full','disk','stopped')) {
    $child = "$name-$variant-child"
    $names.Add($child)
    $version = 4
    switch ($variant) {
      old { $source = @('--from-snapshot',"$name-2"); $version = 2 }
      full { $source = @('--from-snapshot',"$output\$layout-delta.tar.zst",'--snapshot-base',"$name-2") }
      disk { $source = @('--from-snapshot',"$output\$layout-last.tar",'--snapshot-base',"$output\$layout-base.tar.zst",'--disk-only') }
      stopped { $source = @('--from-snapshot',"$name-stopped") }
    }
    Measure-Msb "$layout-restore-$variant" (@('create','-n',$child) + $source)
    Measure-Msb "$layout-restored-$variant-data" @('exec',$child,'--','sh','-c',('sha256sum -c /expected && test $(cat /version) = ' + $version))
    $memoryCheck = if ($variant -in @('old','full')) { 'test $(cat /dev/shm/ram-marker) = volatile' } else { 'test ! -e /dev/shm/ram-marker' }
    Measure-Msb "$layout-restored-$variant-memory" @('exec',$child,'--','sh','-c',$memoryCheck)
    Measure-Msb "$layout-stop-$variant" @('stop',$child)
  }
 }
 'passed' | Set-Content "$taskRoot\live.status"
} catch {
 'failed' | Set-Content "$taskRoot\live.status"
 $_ | Out-String | Set-Content "$taskRoot\live.error"
 throw
} finally {
 $ErrorActionPreference = 'Continue'
 foreach ($name in $names) { & $bin stop $name *> $null }
}
