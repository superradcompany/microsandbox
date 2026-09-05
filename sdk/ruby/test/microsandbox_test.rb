# frozen_string_literal: true

require "rbconfig"
require "test/unit"
require "timeout"
require_relative "../lib/microsandbox"

class MicrosandboxTest < Test::Unit::TestCase
  # Mirrors sdk/python/microsandbox/errors.py plus the Go SDK's snapshot,
  # exec-failed, and volume-already-exists granularity.
  ERROR_CLASSES = %i[
    InvalidConfigError NoDefaultCommandError
    SandboxNotFoundError SandboxNotRunningError SandboxAlreadyExistsError SandboxStillRunningError
    ExecTimeoutError ExecFailedError
    FilesystemError PathNotFoundError
    VolumeNotFoundError VolumeAlreadyExistsError ImageNotFoundError ImageInUseError ImagePullFailedError
    SnapshotNotFoundError SnapshotAlreadyExistsError SnapshotSandboxRunningError
    SnapshotImageMissingError SnapshotIntegrityError SnapshotMigrationError
    NetworkPolicyError SecretViolationError TlsError
    IoError
    MetricsDisabledError MetricsUnavailableError
    UnsupportedOperationError CloudHttpError UnsupportedError
  ].freeze

  def test_version_is_available
    assert_match(/\A\d+\.\d+\.\d+\z/, Microsandbox.version)
  end

  def test_installation_probe_returns_boolean
    assert_includes [true, false], Microsandbox.installed?
  end

  def test_builder_configuration_is_chainable
    proxy = Microsandbox::OutboundProxy.socks5("127.0.0.1:1080")
      .credentials("sandbox", Microsandbox::SecretSource.env("SOCKS5_PASSWORD"))

    builder = Microsandbox::Sandbox.builder("ruby-test")
      .image("alpine")
      .cpus(2)
      .memory(256)
      .env("GREETING", "hello")
      .label("suite", "ruby")
      .workdir("/tmp")
      .proxy(proxy)
      .vsock("/run/host-api.sock", 5000)
      .vsock_dgram("/run/events.sock", 5001)

    assert_instance_of Microsandbox::SandboxBuilder, builder
  end

  def test_socks4_proxy_user_id_is_chainable
    proxy = Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").user_id("sandbox")

    assert_instance_of Microsandbox::OutboundProxy, proxy
  end

  def test_proxy_authentication_is_protocol_specific
    password = Microsandbox::SecretSource.env("SOCKS5_PASSWORD")

    assert_raise(ArgumentError) do
      Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").credentials("sandbox", password)
    end
    assert_raise(ArgumentError) do
      Microsandbox::OutboundProxy.socks5("127.0.0.1:1080").user_id("sandbox")
    end
  end

  def test_secret_source_rejects_an_empty_environment_variable
    assert_raise(ArgumentError) { Microsandbox::SecretSource.env("") }
  end

  def test_create_accepts_proxy_keyword
    proxy = Microsandbox::OutboundProxy.socks5("not-an-address")

    error = assert_raise(Microsandbox::Error) do
      Microsandbox::Sandbox.create("ruby-test", proxy: proxy)
    end

    assert_match(/invalid SOCKS5 proxy address/, error.message)
  end

  def test_create_applies_protocol_specific_proxy_authentication
    socks4 = Microsandbox::OutboundProxy.socks4("127.0.0.1:1080").user_id("")
    socks4_error = assert_raise(Microsandbox::Error) do
      Microsandbox::Sandbox.create("ruby-test", proxy: socks4)
    end

    password = Microsandbox::SecretSource.env("SOCKS5_PASSWORD")
    socks5 = Microsandbox::OutboundProxy.socks5("127.0.0.1:1080").credentials("", password)
    socks5_error = assert_raise(Microsandbox::Error) do
      Microsandbox::Sandbox.create("ruby-test", proxy: socks5)
    end

    assert_match(/invalid SOCKS4 user ID/, socks4_error.message)
    assert_match(/invalid SOCKS5 credentials/, socks5_error.message)
  end

  def test_unknown_create_keyword_is_rejected_before_runtime_start
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", unsupported_option: true)
    end

    assert_match(/unknown keyword/, error.message)
  end

  def test_invalid_sandbox_name_is_reported_as_sdk_error
    error = assert_raise(Microsandbox::InvalidConfigError) { Microsandbox::Sandbox.create("") }

    assert_kind_of Microsandbox::Error, error
    assert_equal "invalid-config", error.code
  end

  def test_invalid_network_host_raises_network_policy_error
    # The policy is built while parsing the create options, before any
    # runtime call, so a malformed hostname fails without a sandbox.
    error = assert_raise(Microsandbox::NetworkPolicyError) do
      Microsandbox::Sandbox.create("ruby-test", network: { allowed_hosts: ["not a host!"], allowed_ports: [443] })
    end

    assert_kind_of Microsandbox::Error, error
    assert_equal "network-policy-error", error.code
    assert_match(/not a host!/, error.message)
  end

  def test_typed_error_is_rescued_by_base_error
    rescued = begin
      Microsandbox::Sandbox.create("")
    rescue Microsandbox::Error => error
      error
    end

    assert_instance_of Microsandbox::InvalidConfigError, rescued
  end

  def test_base_error_code
    assert_equal "microsandbox-error", Microsandbox::Error.code
    assert_equal "microsandbox-error", Microsandbox::Error.new("boom").code
  end

  def test_error_classes_are_direct_subclasses_of_error
    defined_classes = Microsandbox.constants.select do |name|
      constant = Microsandbox.const_get(name)
      constant.is_a?(Class) && constant < Microsandbox::Error
    end

    assert_equal ERROR_CLASSES.sort, defined_classes.sort
    ERROR_CLASSES.each do |name|
      assert_equal Microsandbox::Error, Microsandbox.const_get(name).superclass, name
    end
  end

  def test_error_codes_are_unique_kebab_case
    codes = ERROR_CLASSES.map { |name| Microsandbox.const_get(name).code }

    codes.each { |code| assert_match(/\A[a-z]+(-[a-z]+)*\z/, code) }
    assert_equal codes, codes.uniq
    assert_not_include codes, Microsandbox::Error.code
    assert_equal "exec-timeout", Microsandbox::ExecTimeoutError.new("boom").code
  end

  def test_unsupported_error_attributes_default_to_nil
    error = Microsandbox::UnsupportedError.new("boom")

    assert_nil error.operation
    assert_nil error.hint
    assert_equal "unsupported", error.code
  end

  def test_missing_sandbox_raises_sandbox_not_found_error
    # The local backend answers from its catalog without booting a VM.
    name = "does-not-exist-#{Process.pid}-#{rand(1_000_000)}"

    error = assert_raise(Microsandbox::SandboxNotFoundError) { Microsandbox::Sandbox.get(name) }

    assert_kind_of Microsandbox::Error, error
    assert_equal "sandbox-not-found", error.code
  end

  def test_unsupported_error_carries_operation_and_hint
    # The cloud backend rejects `replace:` while building the request, before
    # any network access, so this needs neither credentials nor connectivity.
    # Selecting a backend is process-global, so the probe runs in a separate
    # Ruby process and this process keeps its backend selection. A fork would
    # not do: on macOS the cloud client initializes Foundation classes on
    # first use, which the Objective-C runtime refuses in a forked child.
    backend_kind = Microsandbox.default_backend_kind
    script = <<~RUBY
      require "microsandbox"
      Microsandbox.use_cloud_backend!("test-key", url: "http://127.0.0.1:9")
      begin
        Microsandbox::Sandbox.create("ruby-test", image: "alpine", replace: true)
        puts "no error raised"
      rescue Microsandbox::UnsupportedError => error
        puts error.message, error.operation, error.hint
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)

    output = IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)

    assert_true $?.success?
    assert_equal [
      "sandbox.create is not supported by this backend: the replace option is not accepted here",
      "sandbox.create",
      "the replace option is not accepted here"
    ], output.lines(chomp: true)
    assert_equal backend_kind, Microsandbox.default_backend_kind
  end

  def test_with_is_available
    assert_respond_to Microsandbox::Sandbox, :with
  end

  def test_connect_or_create_is_available
    assert_respond_to Microsandbox::Sandbox, :connect_or_create
    assert_respond_to Microsandbox::Sandbox.builder("ruby-test"), :connect_or_create
  end

  def test_entrypoint_rejects_non_string_elements
    builder = Microsandbox::Sandbox.builder("ruby-test")
    assert_raise(TypeError) { builder.entrypoint(["sh", 1]) }
  end

  def test_with_preserves_block_error_when_stop_also_fails
    fake = Object.new
    fake.define_singleton_method(:stop) { raise "stop failed" }
    sandbox_class = Class.new(Microsandbox::Sandbox)
    sandbox_class.define_singleton_method(:create) { |*, **| fake }

    error = assert_raise(ArgumentError) do
      sandbox_class.with("ruby-test") { raise ArgumentError, "block failed" }
    end

    assert_equal "block failed", error.message
  end

  def test_with_raises_stop_error_after_successful_block
    fake = Object.new
    fake.define_singleton_method(:stop) { raise "stop failed" }
    sandbox_class = Class.new(Microsandbox::Sandbox)
    sandbox_class.define_singleton_method(:create) { |*, **| fake }

    error = assert_raise(RuntimeError) do
      sandbox_class.with("ruby-test") { :ok }
    end

    assert_equal "stop failed", error.message
  end

  def test_native_runtime_rebuilds_after_fork
    omit("fork is unavailable") unless Process.respond_to?(:fork)

    Microsandbox::Sandbox.list(limit: 1)
    reader, writer = IO.pipe
    child = fork do
      reader.close
      begin
        Microsandbox::Sandbox.list(limit: 1)
        writer.write("ok")
      rescue StandardError => error
        writer.write("#{error.class}: #{error.message}")
      ensure
        writer.close
        exit! 0
      end
    end
    writer.close

    result = Timeout.timeout(10) { reader.read }
    Process.wait(child)

    assert_equal "ok", result
  ensure
    reader&.close
    writer&.close
    if child
      begin
        Process.kill("KILL", child)
        Process.wait(child)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end
end
