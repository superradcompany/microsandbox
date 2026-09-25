# frozen_string_literal: true

require "fileutils"
require "test/unit"

require "microsandbox/binaries"

class MicrosandboxBinariesTest < Test::Unit::TestCase
  def setup
    @libexec = File.expand_path("../libexec", __dir__)
    @original_spec = Gem.loaded_specs[Microsandbox::Binaries::GEM_NAME]
    FileUtils.mkdir_p(@libexec)
    File.write(File.join(@libexec, "msb"), "fixture")
    File.write(File.join(@libexec, firmware_name), "fixture")
    activate_for(Gem::Platform.local)
  end

  def teardown
    FileUtils.rm_rf(@libexec)
    if @original_spec
      Gem.loaded_specs[Microsandbox::Binaries::GEM_NAME] = @original_spec
    else
      Gem.loaded_specs.delete(Microsandbox::Binaries::GEM_NAME)
    end
  end

  def test_resolves_absolute_runtime_paths
    assert_equal File.join(@libexec, "msb"), Microsandbox::Binaries.msb_path
    assert_equal File.join(@libexec, firmware_name), Microsandbox::Binaries.libkrunfw_path
    assert_true File.absolute_path?(Microsandbox::Binaries.msb_path)
    assert_true File.absolute_path?(Microsandbox::Binaries.libkrunfw_path)
  end

  def test_rejects_a_gem_for_another_platform
    other = %w[arm64-darwin x86_64-linux-gnu aarch64-linux-gnu]
            .map { |name| Gem::Platform.new(name) }
            .find { |platform| !(platform === Gem::Platform.local) }
    activate_for(other)

    error = assert_raise(Microsandbox::Binaries::PlatformError) do
      Microsandbox::Binaries.msb_path
    end

    assert_include error.message, Gem::Platform.local.to_s
  end

  def test_requires_rubygems_activation
    Gem.loaded_specs.delete(Microsandbox::Binaries::GEM_NAME)

    error = assert_raise(Microsandbox::Binaries::PlatformError) do
      Microsandbox::Binaries.msb_path
    end

    assert_include error.message, "not activated through RubyGems"
  end

  def test_requires_exactly_one_versioned_firmware_library
    File.write(File.join(@libexec, second_firmware_name), "fixture")

    error = assert_raise(Microsandbox::Binaries::PlatformError) do
      Microsandbox::Binaries.libkrunfw_path
    end

    assert_include error.message, Gem::Platform.local.to_s
  end

  private

  def activate_for(platform)
    spec = Gem::Specification.new do |candidate|
      candidate.name = Microsandbox::Binaries::GEM_NAME
      candidate.version = Microsandbox::Binaries::VERSION
      candidate.platform = platform
    end
    Gem.loaded_specs[Microsandbox::Binaries::GEM_NAME] = spec
  end

  def firmware_name
    Gem::Platform.local.os == "darwin" ? "libkrunfw.4.dylib" : "libkrunfw.so.4.1.0"
  end

  def second_firmware_name
    Gem::Platform.local.os == "darwin" ? "libkrunfw.5.dylib" : "libkrunfw.so.5.1.0"
  end
end
