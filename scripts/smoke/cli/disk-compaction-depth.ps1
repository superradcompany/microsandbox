$ErrorActionPreference = 'Stop'
$taskRoot = $env:QUAL_ROOT
if (!$taskRoot) { throw 'Set QUAL_ROOT to an isolated qualification root containing home/bin/msb.exe and matching firmware.' }
$prefix = if ($env:QUAL_PREFIX) { $env:QUAL_PREFIX } else { 'compact-depth' }
$env:MSB_HOME = "$taskRoot\home"
$env:MSB_LIBKRUNFW_PATH = "$taskRoot\home\lib\libkrunfw-windows.dll"
$env:PATH = "$taskRoot\home\lib;$env:PATH"
$bin = "$taskRoot\home\bin\msb.exe"
$output = "$taskRoot\depth"
New-Item -ItemType Directory -Force $output | Out-Null
$names = [Collections.Generic.List[string]]::new()
function M([string[]]$command) {
  $ErrorActionPreference = 'Continue'
  & $bin @command
  $result = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($result -ne 0) { throw "msb failed ($result): $command" }
}
try {
 foreach ($layout in @('managed','flat')) {
  $name = "$prefix-$layout"; $names.Add($name)
  $spec = if ($layout -eq 'flat') { 'flat:512M' } else { '512M' }
  if (Test-Path "$output\$layout-depth-64.json") {
    M @('start',$name)
  } else {
   M @('create','-n',$name,'--root-disk',$spec,'-m','128M','--max-duration','30m','alpine')
   M @('exec',$name,'--','sh','-c','dd if=/dev/urandom of=/payload bs=1048576 count=4 2>/dev/null; sha256sum /payload >/expected; sync')
   foreach ($generation in 1..64) {
    M @('exec',$name,'--','sh','-c',"echo $generation >/version; sync")
    M @('snapshot','create',"$name-$generation",'--from',$name,'--full') *> "$output\$layout-$generation.log"
    if ($generation -in @(1,4,16,64)) { M @('modify',$name,'--compact','--dry-run','--format','json') > "$output\$layout-depth-$generation.json" }
   }
  }
  $writerArgs = 'exec ' + $name + ' -- sh -c "i=0; while [ ! -e /writer-stop ]; do i=$((i+1)); echo $i >>/writes; sync; done"'
  $writer = Start-Process -FilePath $bin -ArgumentList $writerArgs -PassThru -NoNewWindow -RedirectStandardOutput "$output\$layout-writer.out" -RedirectStandardError "$output\$layout-writer.err"
  # Give the writer's CLI process time to finish normal install/schema admission. Its guest
  # workload keeps writing for the entire compaction; this is not a pause of that workload.
  Start-Sleep -Milliseconds 750
  M @('modify',$name,'--compact','--layers','32','--format','json') | Tee-Object "$output\$layout-compact-32.json"
  M @('exec',$name,'--','sh','-c','touch /writer-stop; sync')
  if (!$writer.WaitForExit(10000)) { throw 'concurrent writer failed to finish' }
  if ($null -ne $writer.ExitCode -and $writer.ExitCode -ne 0) { throw "writer exit $($writer.ExitCode)" }
  M @('exec',$name,'--','sh','-c','seq $(wc -l < /writes) >/want; cmp /writes /want && test -s /writes && sha256sum -c /expected && test $(cat /version) = 64 && echo durable >/after && sync')
  M @('stop',$name)
  M @('modify',$name,'--compact','--format','json') | Tee-Object "$output\$layout-compact-all.json"
  M @('start',$name)
  M @('exec',$name,'--','sh','-c','sha256sum -c /expected && test $(cat /version) = 64 && test $(cat /after) = durable')
  M @('stop',$name)
  $child="$name-child"; $names.Add($child)
  M @('create','-n',$child,'--from-snapshot',"$name-16")
  M @('exec',$child,'--','sh','-c','sha256sum -c /expected && test $(cat /version) = 16')
  M @('stop',$child)
  "$layout 65->34->2 layers, concurrent writer, restart and old restore PASS" | Tee-Object -FilePath "$output\results.txt" -Append
 }
} finally {
 $ErrorActionPreference='Continue'
 foreach ($name in $names) { & $bin stop $name *> $null }
}
