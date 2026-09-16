# frozen_string_literal: true

# Run with an installed candidate gem in the driver's isolated GEM_HOME. The
# driver records an unavailable released lane when RubyGems has no matching gem.
require "json"
require "digest"
require "open3"

report = {
  language: "ruby", case: ENV["MSB_COMPAT_CASE"],
  expected_sdk_version: ENV["MSB_COMPAT_SDK_VERSION"],
  passed: [], not_applicable: [], runtime_evidence: [], status: "failed"
}

def assert(condition, message)
  raise message unless condition
end

def check_output(output, expected)
  assert(output.success? && output.stdout == expected,
         "exec mismatch: exit=#{output.exit_code} stdout=#{output.stdout.inspect} stderr=#{output.stderr.inspect}")
end

def cleanup(name)
  handle = Microsandbox::Sandbox.get(name)
  handle.stop if handle.status == "running"
  handle.remove
end

def verify_runtime(report, name)
  commands = [
    [ENV.fetch("MSB_COMPAT_PYTHON", "python3"), ENV.fetch("MSB_COMPAT_VERIFY_RUNTIME"), name],
    [ENV.fetch("MSB_COMPAT_CLI"), "inspect", name, "--format", "json"]
  ]
  commands.each do |command|
    stdout, stderr, status = Open3.capture3(*command)
    assert(status.success?, "#{command.inspect} failed: #{stderr}")
    report[:runtime_evidence] << JSON.parse(stdout)
  end
  report[:passed] << "#{name}/runtime-identity-cli-inspect"
end

def lifecycle(report)
  name = "compat-ruby-#{Process.pid}-0"
  marker = "compat-ruby-#{ENV.fetch('MSB_COMPAT_CASE')}"
  sandbox = nil
  removed = false
  begin
    sandbox = Microsandbox::Sandbox.create(
      name, image: ENV.fetch("MSB_COMPAT_IMAGE"), memory: 256, cpus: 1,
      env: { "MSB_COMPAT_MARKER" => marker }
    )
    report[:passed] << "tmpfs-0/create"
    verify_runtime(report, name)
    check_output(sandbox.exec("/bin/sh", ["-c", 'printf "%s" "$MSB_COMPAT_MARKER"']), marker)
    report[:passed] << "tmpfs-0/exec-env"
    # A root-disk path is persistent even when the image mounts /tmp as tmpfs.
    sandbox.fs.write("/compat-persistent.txt", marker)
    assert(sandbox.fs.read("/compat-persistent.txt") == marker, "filesystem round trip mismatch")
    report[:passed] << "tmpfs-0/filesystem"
    sandbox.stop
    sandbox = Microsandbox::Sandbox.start(name)
    verify_runtime(report, name)
    assert(sandbox.fs.read("/compat-persistent.txt") == marker, "root data lost after stop/start")
    report[:passed] << "tmpfs-0/stop-start-persistence"
    sandbox.stop
    Microsandbox::Sandbox.remove(name)
    removed = true
    report[:passed] << "tmpfs-0/remove"
  ensure
    # Cleanup errors fail an otherwise passing scenario, but preserve a primary
    # compatibility failure so the report identifies its original boundary.
    primary_error = $!
    if sandbox && !removed
      begin
        cleanup(name)
      rescue StandardError => error
        raise error unless primary_error
        warn "cleanup #{name}: #{error.message}"
      end
    end
  end
end

def deny_network(report)
  name = "compat-ruby-#{Process.pid}-deny"
  sandbox = nil
  begin
    sandbox = Microsandbox::Sandbox.create(
      name, image: ENV.fetch("MSB_COMPAT_IMAGE"), memory: 256, cpus: 1, network: :none
    )
    verify_runtime(report, name)
    # Ruby's :none contract disables the network device. Assert that directly;
    # a failed external request alone would also pass during an unrelated outage.
    output = sandbox.shell("awk 'NR > 2 && $1 != \"lo:\" { bad=1 } END { exit bad }' /proc/net/dev", timeout: 10)
    assert(output.success?, "network:none exposed a non-loopback network interface")
    check_output(sandbox.exec("/bin/sh", ["-c", "printf compat-network-disabled"]), "compat-network-disabled")
    report[:passed] << "network/configured-none-no-external-interface"
    report[:passed] << "network/exec-with-network-disabled"
  ensure
    primary_error = $!
    if sandbox
      begin
        cleanup(name)
      rescue StandardError => error
        raise error unless primary_error
        warn "cleanup #{name}: #{error.message}"
      end
    end
  end
end

begin
  %w[MSB_COMPAT_IMAGE MSB_COMPAT_REPORT MSB_COMPAT_CASE MSB_COMPAT_SDK_VERSION MSB_COMPAT_SDK_ROOT MSB_HOME MSB_COMPAT_CLI MSB_COMPAT_VERIFY_RUNTIME].each do |key|
    assert(ENV[key] && !ENV[key].empty?, "#{key} is required")
  end
  # Requiring the exact installed gem prevents a checkout on RUBYLIB from being
  # mistaken for a published or packaged SDK in compatibility evidence.
  gem "microsandbox", "=#{ENV.fetch('MSB_COMPAT_SDK_VERSION').delete_prefix('v')}"
  require "microsandbox"
  spec = Gem.loaded_specs.fetch("microsandbox")
  sdk_root = File.realpath(ENV.fetch("MSB_COMPAT_SDK_ROOT")) + "/"
  assert(File.realpath(spec.full_gem_path).start_with?(sdk_root), "gem escaped the isolated SDK installation")
  report[:sdk_version] = Microsandbox::VERSION
  report[:gem] = { version: spec.version.to_s, path: spec.full_gem_path, platform: spec.platform.to_s }
  expected = ENV.fetch("MSB_COMPAT_SDK_VERSION").delete_prefix("v")
  assert(Microsandbox::VERSION == expected, "Ruby SDK version mismatch")
  assert(Microsandbox.version == expected, "native Ruby SDK version mismatch")
  loaded = $LOADED_FEATURES.select { |path| path.match?(%r{/microsandbox(?:/[^/]+)?/microsandbox\.(?:so|bundle|dll)\z}) }
  assert(loaded.length == 1, "expected one loaded microsandbox native extension, got #{loaded.inspect}")
  path = File.realpath(loaded.first)
  assert(path.start_with?(File.realpath(spec.full_gem_path) + "/") ||
         path.start_with?(File.realpath(spec.extension_dir) + "/"), "native extension is outside the selected gem")
  report[:native] = { sdk_version: Microsandbox.version, loaded_path: path, loaded_sha256: Digest::SHA256.file(path).hexdigest }
  if ENV["MSB_COMPAT_NATIVE_SHA256"]
    assert(report[:native][:loaded_sha256] == ENV["MSB_COMPAT_NATIVE_SHA256"], "native artifact SHA256 mismatch")
  end
  report[:passed] << "sdk-native-identity"
  # The current Ruby API does not expose custom mounts or snapshot restoration.
  # Record these gaps explicitly; never substitute a CLI call for SDK coverage.
  ["tmpfs-1", "tmpfs-3"].each do |name|
    report[:not_applicable] << { case: name, reason: "Ruby SDK does not expose custom mounts" }
  end
  report[:not_applicable] << { case: "disk-snapshot/restore-persistence", reason: "Ruby SDK does not expose snapshot restoration" }
  report[:not_applicable] << { case: "network/allow-all-positive-control", reason: "Ruby SDK does not expose allow-all policy; network:none is verified through the absent network device and working exec" }
  lifecycle(report)
  deny_network(report)
  report[:status] = "passed"
rescue StandardError, LoadError => error
  report[:error] = "#{error.class}: #{error.message}"
  report[:backtrace] = error.backtrace
ensure
  output = JSON.pretty_generate(report)
  puts output
  File.write(ENV.fetch("MSB_COMPAT_REPORT"), output + "\n") if ENV["MSB_COMPAT_REPORT"]
end

exit(report[:status] == "passed" ? 0 : 1)
