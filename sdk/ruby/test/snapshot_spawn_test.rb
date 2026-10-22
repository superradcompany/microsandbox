# frozen_string_literal: true

require "test/unit"
require "json"
require "securerandom"
require "tmpdir"
require "fileutils"
require "open3"
require "rbconfig"
require_relative "../lib/microsandbox"

# Run against a disposable MSB_HOME; these tests create real guests and assert guest contents.
class SnapshotSpawnTest < Test::Unit::TestCase
  def setup
    omit("set MSB_RUBY_INTEGRATION=1 on a virtualization host") unless ENV["MSB_RUBY_INTEGRATION"] == "1"
    # The path case owns its fixtures and native workers in a separate interpreter.
    return if method_name == "test_local_paths_are_captured_before_progress_and_gc" && ENV["MSB_RUBY_PATH_WORKER"] != "1"

    @names = []
    @group = nil
    @temporary = Dir.mktmpdir("msb-ruby-spawn-")
    source_name = child_name("source")
    source = Microsandbox::Sandbox.create(source_name, image: ENV.fetch("MSB_RUBY_TEST_IMAGE", "alpine:3.19"), cpus: 1, memory: 256)
    assert_true source.shell("printf ruby-snapshot-marker > /root/marker").success?
    source.stop
    created = Microsandbox::Sandbox.get(source_name).snapshot("ruby-history-#{SecureRandom.hex(5)}", record_integrity: true)
    @group = created.snapshot
    @checkpoint = created.checkpoint
    # Neither the group nor member spawn may depend on a surviving source sandbox.
    Microsandbox::Sandbox.get(source_name).remove
    @names.delete(source_name)
  end

  def teardown
    @names&.reverse_each do |name|
      begin
        handle = Microsandbox::Sandbox.get(name)
        handle.stop if handle.status == "running"
        handle.remove
      rescue Microsandbox::SandboxNotFoundError
        nil
      end
    end
    @extra_groups&.reverse_each(&:remove)
    @group&.remove
    FileUtils.remove_entry(@temporary) if @temporary && File.directory?(@temporary)
  end

  def child_name(label)
    name = "ruby-spawn-#{label}-#{SecureRandom.hex(5)}"
    @names << name
    name
  end

  def check_guest(sandbox)
    assert_equal "ruby-snapshot-marker", sandbox.shell("cat /root/marker").stdout.strip
    assert_equal "1", sandbox.shell("nproc").stdout.strip
  end

  def test_group_head_and_exact_member_remain_distinct
    child = @group.spawn_sandbox(name: child_name("head"), cpus: 1, memory: 256, network: :none)
    check_guest(child)
    child.stop
    @group.clear_head
    assert_raise(Microsandbox::InvalidConfigError) { @group.spawn_sandbox(name: child_name("headless")) }
    exact = @checkpoint.spawn_sandbox(name: child_name("exact"), cpus: 1)
    check_guest(exact)
    exact.stop
  end

  def test_destination_hostname_and_init_boot_a_private_child
    # Ruby keeps the existing string init shape; the supplied program is already in the disk.
    child = @group.spawn_sandbox(name: child_name("prepare"))
    assert_true child.shell("printf '#!/bin/sh\nexec sleep 300\n' > /root/child-init; chmod 755 /root/child-init; sync").success?
    created = child.snapshot("ruby-boot-#{SecureRandom.hex(5)}", record_integrity: true)
    @extra_groups = [created.snapshot]
    child.stop
    session = created.checkpoint.spawn_sandbox_with_progress(
      name: child_name("boot"), init: "/root/child-init", hostname: "ruby-child"
    )
    booted = session.result
    check_guest(booted)
    assert_equal "sleep", booted.shell("cat /proc/1/comm").stdout.strip
    assert_equal "ruby-child", booted.shell("hostname").stdout.strip
    booted.kill # The test PID 1 is sleep, which has no shutdown handler.
  end

  def check_command_defaults(child)
    runtime = JSON.parse(Microsandbox::Sandbox.get(child.name).config_json).fetch("runtime")
    assert_equal "/root", runtime.fetch("workdir")
    assert_equal "/bin/ash", runtime.fetch("shell")
    assert_equal ["/bin/sh", "-c"], runtime.fetch("entrypoint")
    assert_equal ["touch /root/default-ran"], runtime.fetch("cmd")
  end

  def test_disk_boot_resource_ceilings
    [false, true].each do |progress|
      options = { name: child_name("ceilings"), cpus: 1, memory: 256, max_cpus: 2, max_memory: 512, labels: { "destination" => "ruby-child" }, workdir: "/root", shell: "/bin/ash", env: { "DEST_VALUE" => "ruby-value" }, entrypoint: ["/bin/sh", "-c"], cmd: ["touch /root/default-ran"] }
      child = progress ? @checkpoint.spawn_sandbox_with_progress(**options).result : @group.spawn_sandbox(**options)
      check_guest(child)
      check_command_defaults(child)
      assert_equal "/root:ruby-value", child.shell('test ! -e /root/default-ran && printf "%s:%s" "$PWD" "$DEST_VALUE"').stdout
      resources = JSON.parse(Microsandbox::Sandbox.get(child.name).config_json).fetch("resources")
      assert_equal 2, resources.fetch("max_cpus")
      assert_equal 512, resources.fetch("max_memory_mib")
      assert_equal "ruby-child", JSON.parse(Microsandbox::Sandbox.get(child.name).config_json).fetch("labels").fetch("destination")
      assert_equal "0-1", child.shell("cat /sys/devices/system/cpu/possible").stdout.strip
      child.stop
    end
    [{ max_cpus: 0 }, { max_memory: 0 }, { cpus: 2, max_cpus: 1 }, { memory: 512, max_memory: 256 }].each do |options|
      name = child_name("invalid-ceiling")
      assert_raise(Microsandbox::InvalidConfigError) { @checkpoint.spawn_sandbox(name: name, **options) }
      assert_raise(Microsandbox::SandboxNotFoundError) { Microsandbox::Sandbox.get(name) }
    end
  end

  def test_imported_unbound_history_can_spawn_but_cannot_capture
    archive = File.join(@temporary, "standalone.msb")
    @checkpoint.save(archive)
    imported = Microsandbox::Snapshot.load("ruby-import-#{SecureRandom.hex(5)}", [archive]).snapshot
    @extra_groups = [imported]
    assert_raise(Microsandbox::InvalidConfigError) { imported.checkpoint }
    child = imported.spawn_sandbox(name: child_name("imported"))
    check_guest(child)
    child.stop
  end

  def test_full_capture_spawns_guest_memory_and_refuses_boot_security_override
    omit("set MSB_RUBY_FULL=1 with full-memory firmware") unless ENV["MSB_RUBY_FULL"] == "1"
    source_name = child_name("full-source")
    source = Microsandbox::Sandbox.create(source_name, image: ENV.fetch("MSB_RUBY_TEST_IMAGE", "alpine:3.19"), cpus: 1, memory: 256, max_cpus: 2, max_memory: 512)
    assert_true source.shell("mkdir -p /mnt/volatile; mount -t tmpfs none /mnt/volatile; printf ruby-full-memory > /mnt/volatile/marker").success?
    created = source.snapshot("ruby-full-#{SecureRandom.hex(5)}", full: true, record_integrity: true)
    @extra_groups = [created.snapshot]
    source.stop
    Microsandbox::Sandbox.get(source_name).remove
    @names.delete(source_name)
    assert_raise(Microsandbox::UnsupportedError) do
      created.checkpoint.spawn_sandbox(name: child_name("full-security"), security: :restricted)
    end
    [{ init: "auto" }, { hostname: "full-child" }].each do |options|
      assert_raise(Microsandbox::InvalidConfigError) do
        created.checkpoint.spawn_sandbox(name: child_name("full-boot"), **options)
      end
    end
    [{ max_cpus: 3 }, { max_memory: 768 }].each do |options|
      name = child_name("full-ceiling")
      error = assert_raise(Microsandbox::InvalidConfigError) { created.checkpoint.spawn_sandbox(name: name, **options) }
      assert_match(/captured CPU and memory geometry/, error.message)
      assert_raise(Microsandbox::SandboxNotFoundError) { Microsandbox::Sandbox.get(name) }
    end
    session = created.checkpoint.spawn_sandbox_with_progress(name: child_name("full"), max_cpus: 2, max_memory: 512, workdir: "/root", shell: "/bin/ash", env: { "DEST_VALUE" => "ruby-full" }, entrypoint: ["/bin/sh", "-c"], cmd: ["touch /root/default-ran"])
    child = session.result
    check_command_defaults(child)
    assert_equal "/root:ruby-full", child.shell('test ! -e /root/default-ran && printf "%s:%s" "$PWD" "$DEST_VALUE"').stdout
    assert_equal "ruby-full-memory", child.shell("cat /mnt/volatile/marker").stdout.strip
    child.stop
  end

  def test_progress_is_separate_from_authoritative_result
    session = @checkpoint.spawn_sandbox_with_progress(name: child_name("progress"), cpus: 1)
    assert_instance_of Microsandbox::PullSession, session
    events = session.progress.to_a
    assert(events.all? { |event| ["pull", "startup"].include?(event.fetch("kind")) })
    child = session.result
    check_guest(child)
    assert_nil session.next_event
    assert_raise(Microsandbox::InvalidConfigError) { session.result }
    session.cancel # Completion already won; this must not affect the returned sandbox.
    check_guest(child)
    child.stop

    # EOF is not success: creation must still report the existing-name refusal.
    failed = @group.spawn_sandbox_with_progress(name: child.name)
    failed.progress.to_a
    assert_raise(Microsandbox::SandboxAlreadyExistsError) { failed.result }
  end

  def test_local_paths_are_captured_before_progress_and_gc
    unless ENV["MSB_RUBY_PATH_WORKER"] == "1"
      # Re-exec rather than fork a running native runtime, and retain the selected addon path.
      stdout, stderr, status = Open3.capture3(
        { "MSB_RUBY_PATH_WORKER" => "1" },
        RbConfig.ruby, *$LOAD_PATH.flat_map { |path| ["-I", path] },
        File.expand_path(__FILE__), "--name", method_name
      )
      assert_predicate status, :success?, "#{stdout}\n#{stderr}"
      return
    end

    File.write(File.join(@temporary, "bound-marker"), "correct-binding")
    original = Dir.pwd
    session = nil
    begin
      Dir.chdir(@temporary)
      bindings = { "/binding" => { bind: ".", readonly: true } }
      session = @group.spawn_sandbox_with_progress(name: child_name("binding"), volumes: bindings)
      bindings.clear # Native work owns converted options, never Ruby heap objects.
    ensure
      Dir.chdir(original)
    end
    @group.clear_head # The in-flight operation must retain its selected checkpoint.
    GC.start(full_mark: true, immediate_sweep: true)
    # Ignoring progress must not block creation; native telemetry is bounded/best effort.
    child = session.result
    assert_equal "correct-binding", child.shell("cat /binding/bound-marker").stdout.strip
    assert_false child.shell("touch /binding/cannot-write").success?
    child.stop
  end

  def test_destination_options_refuse_unknown_or_invalid_controls
    [
      { image: "other" }, { snapshot: "other" },
      { security: :unknown }, { guest_clock: :unknown },
      { ports: [{ host: 0, guest: 80, protocol: :unknown }] },
      { vsock: [{ path: ".", port: 1, unknown: true }] },
      { volumes: { "/data" => { bind: ".", named: "other" } } },
      { volumes: { "/data" => {} } }
    ].each do |options|
      assert_raise(ArgumentError) { @checkpoint.spawn_sandbox(**options) }
      assert_raise(ArgumentError) { @group.spawn_sandbox_with_progress(**options) }
    end
  end

  def test_cancellation_and_inherited_session_refusal
    session = @group.spawn_sandbox_with_progress(name: child_name("cancel"))
    session.cancel
    # Cancellation races successful completion. Either result must be consumed and cleaned up.
    begin
      child = session.result
      check_guest(child)
      child.stop
    rescue Microsandbox::Error => error
      assert_match(/cancel/i, error.message)
    end
    session.progress.to_a # Buffered events may precede EOF even after cancellation.
    assert_nil session.next_event

    return unless Process.respond_to?(:fork)
    pid = fork do
      begin
        session.cancel
        exit! 1
      rescue ArgumentError => error
        exit!(error.message.include?("after fork") ? 0 : 2)
      end
    end
    Process.wait(pid)
    assert_predicate $?, :success?
  end
end
