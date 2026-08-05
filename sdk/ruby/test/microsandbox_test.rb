# frozen_string_literal: true

require "test/unit"
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
end
