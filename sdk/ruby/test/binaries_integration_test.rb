# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "securerandom"
require "test/unit"
require "tmpdir"

require_relative "../lib/microsandbox"

# Boots real sandboxes through an installed microsandbox-binaries companion.
# MSB_RUBY_HOME_RUNTIME_DIR points at the msb and libkrunfw of a complete
# runtime, ideally from another release, to install into MSB_HOME.
class MicrosandboxBinariesIntegrationTest < Test::Unit::TestCase
  IMAGE = ENV.fetch("MSB_RUBY_TEST_IMAGE", "alpine")
  SDK_LIB = File.expand_path("../lib", __dir__)

  # Returns the executable of the msb process running the named sandbox.
  # Shared with the fresh processes below, which run without this class.
  RUNNING_MSB = <<~'RUBY'
    def running_msb(name)
      commands = IO.popen(["ps", "-A", "-ww", "-o", "command="], &:readlines).map(&:split)
      executables = commands.select { |argv| argv.each_cons(2).include?(["--name", name]) }.map(&:first).uniq
      raise "expected one msb executable for #{name}, found #{executables.inspect}" unless executables.one?

      File.realpath(executables.first)
    end
  RUBY
  class_eval(RUNNING_MSB)

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
    assert_equal File.realpath(Microsandbox::Binaries.msb_path), running_msb(name)
    sandbox.stop

    # The local backend snapshots its runtime configuration when it is first
    # created, so the override is exercised in a fresh process.
    override = sandbox_name("override")
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    stdout, stderr, status = Open3.capture3(
      { "MSB_PATH" => "/nonexistent/msb" },
      RbConfig.ruby, "-I", SDK_LIB, "-e", <<~RUBY
        require "microsandbox"
        begin
          Microsandbox::Sandbox.create(#{override.inspect}, image: #{IMAGE.inspect}, cpus: 1, memory: 256, replace: true)
        rescue Microsandbox::Error => error
          puts error.message
          exit 3
        end
      RUBY
    )
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_equal 3, status.exitstatus, "explicit MSB_PATH should make create fail: #{stdout}#{stderr}"
    assert_include stdout, "/nonexistent/msb"
    assert_operator elapsed, :<, 10.0, "explicit MSB_PATH should fail before runtime boot"
  end

  def test_runtime_installed_in_msb_home_takes_precedence_over_the_companion
    runtime_dir = ENV["MSB_RUBY_HOME_RUNTIME_DIR"]
    omit("set MSB_RUBY_HOME_RUNTIME_DIR to a runtime's msb and libkrunfw to check MSB_HOME precedence") unless runtime_dir
    assert defined?(Microsandbox::Binaries), "microsandbox-binaries was not activated"

    # Unix socket paths under MSB_HOME must stay short on macOS.
    Dir.mktmpdir("msbh", "/tmp") do |msb_home|
      home_msb = File.join(msb_home, "bin", "msb")
      FileUtils.mkdir_p([File.dirname(home_msb), File.join(msb_home, "lib")])
      FileUtils.cp(File.join(runtime_dir, "msb"), home_msb, preserve: true)
      firmware = Dir.glob(File.join(runtime_dir, "libkrunfw*"))
      assert_equal 1, firmware.length, "#{runtime_dir} must hold exactly one libkrunfw library"
      FileUtils.cp(firmware.first, File.join(msb_home, "lib"), preserve: true)

      # A fresh process, since the backend has already snapshotted this
      # process's MSB_HOME. It removes its own sandbox: the record lives in
      # this home, out of teardown's reach.
      name = "ruby-bin-home-#{Process.pid}-#{SecureRandom.hex(3)}"
      stdout, stderr, status = Open3.capture3(
        { "MSB_HOME" => msb_home },
        RbConfig.ruby, "-I", SDK_LIB, "-e", <<~RUBY
          require "microsandbox"
          #{RUNNING_MSB}
          abort "microsandbox-binaries was not activated" unless defined?(Microsandbox::Binaries)
          sandbox = Microsandbox::Sandbox.create(#{name.inspect}, image: #{IMAGE.inspect}, cpus: 1, memory: 256, replace: true)
          begin
            puts sandbox.shell("printf home-runtime-ok").stdout
            puts running_msb(#{name.inspect})
          ensure
            sandbox.stop
            Microsandbox::Sandbox.get(#{name.inspect}).remove
          end
        RUBY
      )

      assert_predicate status, :success?, "#{stdout}#{stderr}"
      output, executable = stdout.lines.map(&:chomp)
      assert_equal "home-runtime-ok", output
      assert_equal File.realpath(home_msb), executable
      assert_not_equal File.realpath(Microsandbox::Binaries.msb_path), executable
    end
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
