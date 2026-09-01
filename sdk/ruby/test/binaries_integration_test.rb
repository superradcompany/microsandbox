# frozen_string_literal: true

require "securerandom"
require "test/unit"

require_relative "../lib/microsandbox"

class MicrosandboxBinariesIntegrationTest < Test::Unit::TestCase
  IMAGE = ENV.fetch("MSB_RUBY_TEST_IMAGE", "alpine")

  def setup
    @names = []
    omit("set MSB_RUBY_BINARIES_INTEGRATION=1 to run the companion-gem boot smoke") unless ENV["MSB_RUBY_BINARIES_INTEGRATION"] == "1"
  end

  def teardown
    @names.each do |name|
      sandbox = Microsandbox::Sandbox.get(name)
      sandbox.stop if sandbox.status == "running"
      sandbox.remove
    rescue Microsandbox::Error
      nil
    end
  end

  def test_bundled_runtime_boots_and_environment_override_still_fails_fast
    assert defined?(Microsandbox::Binaries), "microsandbox-binaries was not activated"
    assert_nil ENV["MSB_PATH"], "MSB_PATH must be unset for the bundled-runtime boot assertion"
    assert_nil ENV["MSB_LIBKRUNFW_PATH"],
               "MSB_LIBKRUNFW_PATH must be unset for the bundled-runtime boot assertion"
    assert_false path_contains_msb?, "PATH must be scrubbed of msb for this acceptance test"
    msb_home = ENV["MSB_HOME"]
    assert_not_nil msb_home, "MSB_HOME must point to the isolated integration-test home"
    assert_false File.exist?(File.join(msb_home, "bin", "msb"))

    name = sandbox_name("boot")
    sandbox = Microsandbox::Sandbox.create(
      name,
      image: IMAGE,
      cpus: 1,
      memory: 256,
      replace: true
    )
    output = sandbox.shell("printf binaries-gem-ok")

    assert_true output.success?
    assert_equal "binaries-gem-ok", output.stdout
    sandbox.stop

    ENV["MSB_PATH"] = "/nonexistent/msb"
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raise(Microsandbox::Error) do
      Microsandbox::Sandbox.create(
        sandbox_name("override"),
        image: IMAGE,
        cpus: 1,
        memory: 256,
        replace: true
      )
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_include error.message, "No such file or directory"
    assert_operator elapsed, :<, 10.0, "explicit MSB_PATH should fail before runtime boot"
  ensure
    ENV.delete("MSB_PATH")
  end

  private

  def path_contains_msb?
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? do |directory|
      File.file?(File.join(directory, "msb"))
    end
  end

  def sandbox_name(label)
    name = "ruby-bin-#{label}-#{Process.pid}-#{SecureRandom.hex(3)}"
    @names << name
    name
  end
end
