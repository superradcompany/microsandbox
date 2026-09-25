# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "test/unit"
require "tmpdir"

require_relative "../lib/microsandbox/version"

class MicrosandboxBinariesHookupTest < Test::Unit::TestCase
  SDK_LIB = File.expand_path("../lib", __dir__)

  # Subprocesses see no installed gems unless a test installs some, so a
  # companion in the ambient GEM_HOME cannot shadow the load-path stubs.
  def setup
    @empty_gem_home = Dir.mktmpdir
  end

  def teardown
    FileUtils.rm_rf(@empty_gem_home)
  end

  def test_require_is_silent_when_companion_gem_is_absent
    Dir.mktmpdir do |directory|
      write_native_stub(directory)

      stdout, stderr, status = run_ruby(
        "--disable-gems",
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; puts "ready"'
      )

      assert_predicate status, :success?
      assert_equal "ready\n", stdout
      assert_equal "", stderr
    end
  end

  def test_matching_companion_registers_packaged_msb_and_leaves_env_alone
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory)
      # The hookup registers only the packaged msb (never the explicit
      # setters), and it must not touch an explicit MSB_PATH while doing so.
      write_companion_stub(directory)

      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; puts ENV.fetch("MSB_PATH")',
        env: { "MSB_HOOK_CALLS" => calls, "MSB_PATH" => "/explicit/msb" }
      )

      assert_predicate status, :success?, stderr
      assert_equal "/explicit/msb\n", stdout
      assert_equal "", stderr
      assert_equal "packaged_msb=/bundled/msb\n", File.read(calls)
    end
  end

  def test_companion_payload_is_validated_before_registration
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory)
      write_companion_stub(directory, broken_firmware: true)

      _stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"',
        env: { "MSB_HOOK_CALLS" => calls }
      )

      assert_false status.success?
      assert_include stderr, "broken firmware payload"
      assert_false File.exist?(calls)
    end
  end

  def test_load_error_inside_present_companion_is_not_swallowed
    Dir.mktmpdir do |directory|
      write_native_stub(directory)
      companion = File.join(directory, "lib", "microsandbox", "binaries.rb")
      FileUtils.mkdir_p(File.dirname(companion))
      File.write(companion, 'require "missing_microsandbox_binaries_dependency"')

      _stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"'
      )

      assert_false status.success?
      assert_include stderr, "missing_microsandbox_binaries_dependency"
    end
  end

  def test_missing_entry_file_is_not_swallowed_for_an_activated_companion
    Dir.mktmpdir do |directory|
      write_native_stub(directory)

      _stdout, stderr, status = run_ruby(
        "--disable-gems",
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", <<~'RUBY',
          require "rubygems"
          spec = Gem::Specification.new do |candidate|
            candidate.name = "microsandbox-binaries"
            candidate.version = "0.0.0"
          end
          Gem.loaded_specs["microsandbox-binaries"] = spec
          require "microsandbox"
        RUBY
        env: {
          "GEM_HOME" => File.join(directory, "gems"),
          "GEM_PATH" => File.join(directory, "gems")
        }
      )

      assert_false status.success?
      assert_include stderr, "microsandbox/binaries"
    end
  end

  def test_companion_of_another_version_is_skipped_with_a_warning
    [other_patch_version, other_series_version].each do |version|
      Dir.mktmpdir do |directory|
        calls = File.join(directory, "calls")
        write_native_stub(directory)
        write_companion_stub(directory, version: version)

        stdout, stderr, status = run_ruby(
          "-I", File.join(directory, "lib"),
          "-I", SDK_LIB,
          "-e", 'require "microsandbox"; puts "ready"',
          env: { "MSB_HOOK_CALLS" => calls }
        )

        assert_predicate status, :success?, stderr
        assert_equal "ready\n", stdout
        assert_include stderr, "ignoring microsandbox-binaries #{version}"
        assert_include stderr, "microsandbox #{Microsandbox::VERSION}"
        assert_include stderr, "MSB_PATH"
        assert_false File.exist?(calls), "a companion of another version must not set the SDK tier"
      end
    end
  end

  def test_installed_companion_matching_the_sdk_wins_over_newer_ones
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory)
      gem_home = File.join(directory, "gems")
      # Without selection, RubyGems would activate the newest installed
      # version, which core would refuse to launch.
      [Microsandbox::VERSION, other_patch_version, other_series_version].each do |version|
        install_companion_stub(gem_home, version)
      end

      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; puts Microsandbox::Binaries::VERSION',
        env: { "MSB_HOOK_CALLS" => calls }.merge(gem_env(gem_home))
      )

      assert_predicate status, :success?, stderr
      assert_equal "#{Microsandbox::VERSION}\n", stdout
      assert_equal "", stderr
      assert_equal "packaged_msb=/bundled/#{Microsandbox::VERSION}/msb\n", File.read(calls)
    end
  end

  def test_installed_companions_of_other_versions_only_are_skipped_without_loading
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory)
      gem_home = File.join(directory, "gems")
      [other_patch_version, other_series_version].each { |version| install_companion_stub(gem_home, version) }

      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; p defined?(Microsandbox::Binaries)',
        env: { "MSB_HOOK_CALLS" => calls }.merge(gem_env(gem_home))
      )

      assert_predicate status, :success?, stderr
      assert_equal "nil\n", stdout
      assert_include stderr, "ignoring microsandbox-binaries"
      assert_include stderr, other_patch_version
      assert_include stderr, other_series_version
      assert_include stderr, "must be version #{Microsandbox::VERSION}"
      assert_false File.exist?(calls), "a companion of another version must not set the SDK tier"
    end
  end

  def test_already_activated_companion_is_kept_even_of_another_version
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory)
      gem_home = File.join(directory, "gems")
      [Microsandbox::VERSION, other_patch_version].each { |version| install_companion_stub(gem_home, version) }

      # Stands in for Bundler, which activates the locked version before the
      # application requires anything: the SDK must not swap it out.
      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", <<~RUBY,
          gem "microsandbox-binaries", "= #{other_patch_version}"
          require "microsandbox"
          puts Gem.loaded_specs.fetch("microsandbox-binaries").version
        RUBY
        env: { "MSB_HOOK_CALLS" => calls }.merge(gem_env(gem_home))
      )

      assert_predicate status, :success?, stderr
      assert_equal "#{other_patch_version}\n", stdout
      assert_include stderr, "ignoring microsandbox-binaries #{other_patch_version}"
      assert_false File.exist?(calls)
    end
  end

  private

  def gem_env(gem_home)
    { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home }
  end

  # Installs a minimal microsandbox-binaries into gem_home the way RubyGems
  # lays out an installed gem, with a version-specific msb path.
  def install_companion_stub(gem_home, version)
    spec = Gem::Specification.new do |candidate|
      candidate.name = "microsandbox-binaries"
      candidate.version = version
      candidate.summary = "companion stub"
      candidate.authors = ["test"]
      candidate.files = ["lib/microsandbox/binaries.rb"]
      candidate.require_paths = ["lib"]
    end
    library = File.join(gem_home, "gems", spec.full_name, "lib", "microsandbox", "binaries.rb")
    FileUtils.mkdir_p(File.dirname(library))
    File.write(library, <<~RUBY)
      module Microsandbox
        module Binaries
          VERSION = #{version.inspect}

          def self.msb_path = "/bundled/#{version}/msb"
          def self.libkrunfw_path = "/bundled/#{version}/libkrunfw.4.dylib"
        end
      end
    RUBY
    specifications = File.join(gem_home, "specifications")
    FileUtils.mkdir_p(specifications)
    File.write(File.join(specifications, spec.spec_name), spec.to_ruby)
  end

  def other_series_version
    major, minor, = Microsandbox::VERSION.split(".")
    "#{major}.#{minor.to_i + 1}.0"
  end

  def other_patch_version
    major, minor, patch = Microsandbox::VERSION.split(".")
    "#{major}.#{minor}.#{patch.to_i + 1}"
  end

  def run_ruby(*arguments, env: {})
    Open3.capture3(
      { "RUBYLIB" => nil, "RUBYOPT" => nil }.merge(gem_env(@empty_gem_home)).merge(env),
      RbConfig.ruby,
      *arguments
    )
  end

  # The packaged setter always records: reaching it without MSB_HOOK_CALLS
  # raises KeyError, which fails louder than a silently ignored path would.
  # The explicit setters must never be reached by the hookup.
  def write_native_stub(directory)
    abi = RUBY_VERSION[/\d+\.\d+/]
    path = File.join(directory, "lib", "microsandbox", abi, "microsandbox.rb")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, <<~'RUBY')
      module Microsandbox
        class SandboxBuilder; end
        class Sandbox; end

        def self.record_runtime_path(name, path)
          File.open(ENV.fetch("MSB_HOOK_CALLS"), "a") { |file| file.puts("#{name}=#{path}") }
        end

        def self.set_packaged_msb_path(path) = record_runtime_path("packaged_msb", path)
        def self.set_runtime_msb_path(_path) = raise("hookup reached the explicit msb setter")
        def self.set_runtime_libkrunfw_path(_path) = raise("hookup reached the explicit libkrunfw setter")
      end
    RUBY
  end

  def write_companion_stub(directory, broken_firmware: false, version: Microsandbox::VERSION)
    path = File.join(directory, "lib", "microsandbox", "binaries.rb")
    FileUtils.mkdir_p(File.dirname(path))
    firmware_method = broken_firmware ? 'raise "broken firmware payload"' : '"/bundled/libkrunfw.4.dylib"'
    File.write(path, <<~RUBY)
      module Microsandbox
        module Binaries
          VERSION = #{version.inspect}

          def self.msb_path = "/bundled/msb"
          def self.libkrunfw_path = #{firmware_method}
        end
      end
    RUBY
  end
end
