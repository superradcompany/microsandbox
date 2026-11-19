# Read/execute only the exact fixture; setup/cleanup is external.
require 'microsandbox'
require 'json'
abort 'opt-in required' unless ENV['MSB_REMOTE_AUDIT']=='1'
f=JSON.parse(File.read(ENV.fetch('MSB_INSPECTION_FIXTURE')))
rows=[]
sb=Microsandbox::Sandbox.remote.get(f.fetch('name'))
raise 'identity mismatch' unless sb.id==f.fetch('id')
page=Microsandbox::Sandbox.remote.list
listed=nil
loop do
  listed=page.fetch('sandboxes').find{|s|s.id==sb.id}
  break if listed || !page['next_cursor']
  page=Microsandbox::Sandbox.remote.list(cursor:page['next_cursor'])
end
raise 'fixture missing' unless listed
[['get',sb],['list',listed]].each do |kind, resource|
  checks={
    'config'=>proc { c=resource.config; raise 'inspection mismatch' unless c['kind']=='remote' && c['spec']['runtime']['shell']=='/bin/bash' && c['spec']['runtime']['cmd']==['configured-default'] && c['unavailable'].include?('init') },
    'shell'=>proc {raise 'shell mismatch' unless resource.shell('test -n "$BASH_VERSION" && printf bash').stdout=='bash'},
    'default_command'=>proc {raise 'command mismatch' unless resource.exec_default.stdout=='configured-default'},
    'workdir'=>proc {raise 'workdir mismatch' unless resource.exec('pwd',[]).stdout.strip=='/tmp'}
  }
  checks.each do |label, fn|
    begin; fn.call; rows << {feature:kind+'_'+label,verdict:'PASS'}
    rescue StandardError=>e; rows << {feature:kind+'_'+label,verdict:'FAIL',reason:e.message.gsub(ENV.fetch('MSB_API_KEY'),'[redacted]')}
    ensure; File.write(ENV.fetch('MSB_AUDIT_REPORT'),JSON.pretty_generate(sdk:'ruby',rows:rows)+"\n")
    end
  end
end
if ENV['MSB_INSPECTION_DESTROY'] == '1'
  begin
    sb.destroy
    rows << {feature: 'destroy', verdict: 'PASS'}
    begin
      Microsandbox::Sandbox.remote.get(f.fetch('name'))
      raise 'destroyed fixture still exists'
    rescue Microsandbox::SandboxNotFoundError
      rows << {feature: 'destroy_absent', verdict: 'PASS'}
    end
  rescue StandardError => error
    rows << {feature: 'destroy_or_absence', verdict: 'FAIL', reason: error.message.gsub(ENV.fetch('MSB_API_KEY'), '[redacted]')}
  ensure
    File.write(ENV.fetch('MSB_AUDIT_REPORT'), JSON.pretty_generate(sdk: 'ruby', rows: rows) + "\n")
  end
end
exit(rows.any?{|r|r[:verdict]=='FAIL'} ? 1 : 0)
