# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "test/unit"
require "tmpdir"

class MicrosandboxBinariesHookupTest < Test::Unit::TestCase
  SDK_LIB = File.expand_path("../lib", __dir__)

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

  def test_present_companion_sets_both_runtime_paths
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory, record_calls: true)
      write_companion_stub(directory)

      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; puts "ready"',
        env: { "MSB_HOOK_CALLS" => calls }
      )

      assert_predicate status, :success?
      assert_equal "ready\n", stdout
      assert_equal "", stderr
      assert_equal "msb=/bundled/msb\nlibkrunfw=/bundled/libkrunfw.4.dylib\n", File.read(calls)
    end
  end

  def test_companion_paths_are_resolved_before_either_setter
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory, record_calls: true)
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

  def test_environment_override_remains_above_companion_sdk_tier
    Dir.mktmpdir do |directory|
      calls = File.join(directory, "calls")
      write_native_stub(directory, record_calls: true)
      write_companion_stub(directory)

      stdout, stderr, status = run_ruby(
        "-I", File.join(directory, "lib"),
        "-I", SDK_LIB,
        "-e", 'require "microsandbox"; puts ENV.fetch("MSB_PATH")',
        env: { "MSB_HOOK_CALLS" => calls, "MSB_PATH" => "/explicit/msb" }
      )

      assert_predicate status, :success?, stderr
      assert_equal "/explicit/msb\n", stdout
      assert_equal "msb=/bundled/msb\nlibkrunfw=/bundled/libkrunfw.4.dylib\n", File.read(calls)
    end
  end

  private

  def run_ruby(*arguments, env: {})
    Open3.capture3(
      { "RUBYLIB" => nil, "RUBYOPT" => nil }.merge(env),
      RbConfig.ruby,
      *arguments
    )
  end

  def write_native_stub(directory, record_calls: false)
    abi = RUBY_VERSION[/\d+\.\d+/]
    path = File.join(directory, "lib", "microsandbox", abi, "microsandbox.rb")
    FileUtils.mkdir_p(File.dirname(path))
    recorder = if record_calls
                 <<~'RUBY'
                   def self.record_runtime_path(name, path)
                     File.open(ENV.fetch("MSB_HOOK_CALLS"), "a") { |file| file.puts("#{name}=#{path}") }
                   end
                 RUBY
               else
                 ""
               end
    setters = if record_calls
                <<~RUBY
                  def self.set_runtime_msb_path(path) = record_runtime_path("msb", path)
                  def self.set_runtime_libkrunfw_path(path) = record_runtime_path("libkrunfw", path)
                RUBY
              else
                <<~RUBY
                  def self.set_runtime_msb_path(_path); end
                  def self.set_runtime_libkrunfw_path(_path); end
                RUBY
              end
    File.write(path, <<~RUBY)
      module Microsandbox
        class SandboxBuilder; end
        class Sandbox; end
        #{recorder}
        #{setters}
      end
    RUBY
  end

  def write_companion_stub(directory, msb: "/bundled/msb", firmware: "/bundled/libkrunfw.4.dylib", broken_firmware: false)
    path = File.join(directory, "lib", "microsandbox", "binaries.rb")
    FileUtils.mkdir_p(File.dirname(path))
    firmware_method = broken_firmware ? 'raise "broken firmware payload"' : firmware.inspect
    File.write(path, <<~RUBY)
      module Microsandbox
        module Binaries
          def self.msb_path = #{msb.inspect}
          def self.libkrunfw_path = #{firmware_method}
        end
      end
    RUBY
  end
end
