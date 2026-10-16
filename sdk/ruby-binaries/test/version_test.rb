# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "test/unit"
require "tmpdir"

require_relative "../lib/microsandbox/binaries/version"

class MicrosandboxBinariesVersionTest < Test::Unit::TestCase
  REPOSITORY = File.expand_path("../../..", __dir__)
  VERSION_FILES = %w[
    sdk/ruby/lib/microsandbox/version.rb
    Cargo.toml
  ].freeze

  def test_version_drift_refuses_all_packaging_entrypoints_before_staging
    VERSION_FILES.each do |version_file|
      with_release_tree do |directory|
        path = File.join(directory, version_file)
        File.write(path, File.read(path).sub(Microsandbox::Binaries::VERSION, "999.0.0"))
        staged = File.join(directory, "sdk/ruby-binaries/libexec/msb")
        FileUtils.mkdir_p(File.dirname(staged))
        File.write(staged, "existing payload")

        %w[test package package:arm64_darwin package:x86_64_linux_gnu package:aarch64_linux_gnu].each do |task|
          _stdout, stderr, status = run_rake(directory, task)

          assert_false status.success?, "#{task} accepted drift in #{version_file}"
          assert_include stderr, "version mismatch"
          assert_equal "existing payload", File.read(staged)
        end
      end
    end
  end

  def test_release_bump_keeps_the_companion_in_lockstep
    with_release_tree do |directory|
      parts = Microsandbox::Binaries::VERSION.split(".")
      parts[-1] = (parts.last.to_i + 1).to_s
      next_version = parts.join(".")
      stdout, stderr, status = Open3.capture3(
        "bash", "scripts/bump-version.sh", next_version, chdir: directory
      )

      assert_predicate status, :success?, "#{stdout}\n#{stderr}"
      assert_equal "", stderr
      version_file = File.join(directory, "sdk/ruby-binaries/lib/microsandbox/binaries/version.rb")
      assert_include File.read(version_file), "VERSION = \"#{next_version}\""
      stdout, stderr, status = run_rake(directory, "version_check")
      assert_predicate status, :success?, "#{stdout}\n#{stderr}"
    end
  end

  private

  def run_rake(directory, task)
    Open3.capture3(
      { "RUBYOPT" => nil, "RUBYLIB" => nil },
      RbConfig.ruby, "-S", "rake", task,
      chdir: File.join(directory, "sdk/ruby-binaries")
    )
  end

  def with_release_tree
    Dir.mktmpdir("microsandbox-release") do |directory|
      %w[crates packages].each { |name| FileUtils.mkdir_p(File.join(directory, name)) }
      (VERSION_FILES + %w[
        scripts/bump-version.sh
        sdk/ruby-binaries/Rakefile
        sdk/ruby-binaries/tasks/package.rb
        sdk/ruby-binaries/lib/microsandbox/binaries/version.rb
      ]).each do |relative_path|
        destination = File.join(directory, relative_path)
        FileUtils.mkdir_p(File.dirname(destination))
        FileUtils.cp(File.join(REPOSITORY, relative_path), destination)
      end
      yield directory
    end
  end
end
