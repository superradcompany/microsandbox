# frozen_string_literal: true

require "fileutils"
require "test/unit"
require "tmpdir"

require_relative "../tasks/package"

class MicrosandboxBinariesPackageTest < Test::Unit::TestCase
  FIXTURES = File.expand_path("fixtures", __dir__)

  def test_verifies_checksum_against_fixture
    asset = "payload.txt"
    checksums = File.read(File.join(FIXTURES, "checksums.sha256"))
    expected = Microsandbox::Binaries::Package.expected_sha256!(checksums, asset)

    assert_equal expected,
                 Microsandbox::Binaries::Package.verify_sha256!(File.join(FIXTURES, asset), expected)
  end

  def test_checksum_mismatch_fails_hard
    checksums = File.read(File.join(FIXTURES, "checksums.sha256"))
    expected = Microsandbox::Binaries::Package.expected_sha256!(checksums, "payload.txt")

    Dir.mktmpdir do |directory|
      path = File.join(directory, "payload.txt")
      File.write(path, "tampered")

      error = assert_raise(RuntimeError) do
        Microsandbox::Binaries::Package.verify_sha256!(path, expected)
      end

      assert_include error.message, "rake clobber"
    end
  end

  def test_missing_checksum_entry_fails_hard
    error = assert_raise(RuntimeError) do
      Microsandbox::Binaries::Package.expected_sha256!("", "missing.tar.gz")
    end

    assert_include error.message, "exactly one valid entry"
  end

  def test_version_must_match_the_gem
    error = assert_raise(ArgumentError) do
      Microsandbox::Binaries::Package.package_all!("999.0.0")
    end

    assert_include error.message, Microsandbox::Binaries::VERSION
  end

  def test_gemspec_refuses_generic_path_builds_with_actionable_context
    gemspec = File.expand_path("../microsandbox-binaries.gemspec", __dir__)
    previous_platform = ENV.delete("GEM_PLATFORM")

    error = assert_raise(Gem::InvalidSpecificationException) do
      eval(File.read(gemspec, encoding: "UTF-8"), binding, gemspec)
    end

    assert_include error.message, "build-time-only"
    assert_include error.message, "Gemfile path checkouts"
  ensure
    ENV["GEM_PLATFORM"] = previous_platform if previous_platform
  end

  def test_built_gem_verification_rejects_the_wrong_firmware_flavor
    Dir.mktmpdir do |directory|
      files = %w[
        LICENSE
        README.md
        lib/microsandbox/binaries.rb
        lib/microsandbox/binaries/version.rb
        libexec/msb
        libexec/libkrunfw.4.dylib
      ]
      files.each do |path|
        absolute_path = File.join(directory, path)
        FileUtils.mkdir_p(File.dirname(absolute_path))
        File.write(absolute_path, "fixture")
      end
      FileUtils.chmod(0o755, File.join(directory, "libexec/msb"))

      spec = Gem::Specification.new do |candidate|
        candidate.name = "microsandbox-binaries"
        candidate.version = Microsandbox::Binaries::VERSION
        candidate.platform = Gem::Platform.new("x86_64-linux-gnu")
        candidate.summary = "fixture"
        candidate.authors = ["fixture"]
        candidate.files = files
      end
      gem_path = File.join(directory, spec.file_name)
      Dir.chdir(directory) { Gem::Package.build(spec, true, false, gem_path) }

      error = assert_raise(RuntimeError) do
        Microsandbox::Binaries::Package.verify_built_gem!(
          gem_path,
          "x86_64-linux-gnu",
          Microsandbox::Binaries::VERSION
        )
      end

      assert_include error.message, "unexpected payload"
    end
  end
end
