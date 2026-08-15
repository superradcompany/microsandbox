# frozen_string_literal: true

require "test/unit"
require "timeout"
require_relative "../lib/microsandbox"

class MicrosandboxTest < Test::Unit::TestCase
  def test_version_is_available
    assert_match(/\A\d+\.\d+\.\d+\z/, Microsandbox.version)
  end

  def test_installation_probe_returns_boolean
    assert_includes [true, false], Microsandbox.installed?
  end

  def test_builder_configuration_is_chainable
    builder = Microsandbox::Sandbox.builder("ruby-test")
      .image("alpine")
      .cpus(2)
      .memory(256)
      .env("GREETING", "hello")
      .label("suite", "ruby")
      .workdir("/tmp")
      .vsock("/run/host-api.sock", 5000)
      .vsock_dgram("/run/events.sock", 5001)

    assert_instance_of Microsandbox::SandboxBuilder, builder
  end

  def test_unknown_create_keyword_is_rejected_before_runtime_start
    error = assert_raise(ArgumentError) do
      Microsandbox::Sandbox.create("ruby-test", unsupported_option: true)
    end

    assert_match(/unknown keyword/, error.message)
  end

  def test_invalid_sandbox_name_is_reported_as_sdk_error
    assert_raise(Microsandbox::Error) { Microsandbox::Sandbox.create("") }
  end

  def test_with_is_available
    assert_respond_to Microsandbox::Sandbox, :with
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
