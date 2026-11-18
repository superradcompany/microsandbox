# Opt-in real-provider audit; mutate only the recorded disposable resource names.
require 'microsandbox'
require 'json'
require 'securerandom'
require 'tmpdir'
abort 'Explicit opt-in required' unless ENV['MSB_REMOTE_AUDIT']=='1'
$rows=[];$report=ENV.fetch('MSB_AUDIT_REPORT')
name='audit-rb-'+SecureRandom.hex(4)
File.write($report+'.resources.json',JSON.generate(prefix:name))
def check(feature, expected='success')
  value=yield
  row={feature:feature,verdict:expected=='success' ? 'PASS' : 'FAIL'}
rescue StandardError => e
  reason=case e.message
  when /untagged enum CreateRequest/ then 'config_projection'
  when /unsupported|not supported|local.only/i then 'unsupported'
  when /404|not found/i then 'not_found'
  else e.class.name
  end
  row={feature:feature,verdict:reason=='unsupported' ? 'UNSUPPORTED' : (reason==expected ? 'PASS' : 'FAIL'),reason:reason}
ensure
  $rows << row;puts JSON.generate(row);STDOUT.flush
  File.write($report,JSON.pretty_generate(sdk:'ruby',rows:$rows)+"\n")
  return value
end
def eq(a,b);raise 'assertion failed' unless a==b;end
s=Microsandbox::Sandbox.remote;v=Microsandbox::Volume.remote;p=Microsandbox::Snapshot.remote
sb=vol=snap=nil
begin
  check('context_derive'){Microsandbox::RemoteContext.from_env.with(user_agent:'msb-audit').sandboxes.list}
  [['sandbox',s],['volume',v],['snapshot',p]].each do |kind,c|
    check(kind+'_list'){c.list};check(kind+'_missing','not_found'){c.get(name+'-missing')}
  end
  vol=check('volume_create'){v.builder(name).create}
  check('volume_info'){vol.info} if vol
  sb=check('sandbox_create'){s.create(name,image:'python',ephemeral:false,env:{'AUDIT_ENV'=>'retained'})}
  if sb
    check('sandbox_identity'){eq(s.get(name).id,sb.id);eq(sb.name,name);eq(sb.context.kind,:remote);eq(sb.owns_lifecycle?,false)}
    %w[info status config last_failure_message ensure_running ping touch metrics logs].each{|m|check('sandbox_'+m){sb.public_send(m)}}
    check('get_running'){eq(s.get_running(name).id,sb.id)}
    check('exec'){eq(sb.exec('printf',['exec-ok']).stdout,'exec-ok')}
    check('shell_environment'){eq(sb.shell('printf "$AUDIT_ENV"').stdout,'retained')}
    check('exec_nonzero'){o=sb.shell('printf err >&2; exit 7');eq(o.exit_code,7);eq(o.stderr,'err')}
    check('fs_mkdir'){sb.fs_mkdir('/tmp/audit')}
    check('fs_write'){sb.fs_write('/tmp/audit/a','hello')}
    check('fs_read'){eq(sb.fs_read('/tmp/audit/a'),'hello')}
    check('fs_list'){eq(sb.fs_list('/tmp/audit').length,1)}
    check('fs_stat'){sb.fs_stat('/tmp/audit/a')}
    check('fs_copy'){sb.fs_copy('/tmp/audit/a','/tmp/audit/b')}
    check('fs_rename'){sb.fs_rename('/tmp/audit/b','/tmp/audit/c')}
    check('fs_exists'){eq(sb.fs_exists?('/tmp/audit/c'),true);eq(sb.fs_exists?('/tmp/audit/missing'),false)}
    check('fs_remove'){sb.fs_remove('/tmp/audit/a');sb.fs_remove('/tmp/audit/c');sb.fs_remove_dir('/tmp/audit')}
    check('ssh_exec'){sb.ssh_exec('printf ssh-ok')}
    check('jobs_list'){sb.list_jobs}
    job=check('job_create'){sb.exec_detached('/bin/sh',['-c','printf job-ok; exit 6'])}
    if job
      check('job_wait_repeat'){job.wait;job.wait};check('job_inspect'){job.info};check('job_logs'){job.logs};check('job_get'){eq(sb.get_job(job.id).id,job.id)}
    end
    check('job_kill'){j=sb.exec_detached('sleep',['60']);j.kill;j.wait}
    check('detach'){sb.detach;sb.info}
    check('stop'){sb.stop};check('wait_status'){sb.wait_for_status('stopped')};check('wait_stopped'){sb.wait_until_stopped}
    snap=check('snapshot_create'){b=p.builder(name);b.from_sandbox(name);b.create}
    if snap
      check('snapshot_identity'){eq(p.get(snap.reference).id,snap.id)}
      check('snapshot_manifest'){snap.manifest};check('snapshot_state'){snap.state}
    end
    sb=check('start'){s.start(name)} || sb
    check('restart'){sb=sb.restart}
    check('kill','unsupported'){sb.kill}
    check('stop_again'){sb.stop}
    check('automatic_start'){eq(sb.shell('printf auto').stdout,'auto')}
  end
ensure
  check('snapshot_cleanup'){snap.destroy(false)} if snap
  check('sandbox_cleanup'){sb.destroy} if sb
  check('volume_cleanup'){vol.destroy} if vol
  check('sandbox_cleanup_verified','not_found'){s.get(name)}
  check('volume_cleanup_verified','not_found'){v.get(name)}
  check('snapshot_cleanup_verified','not_found'){p.get(snap.reference)} if snap
end
exit($rows.any?{|r|r[:verdict]=='FAIL'} ? 1 : 0)
