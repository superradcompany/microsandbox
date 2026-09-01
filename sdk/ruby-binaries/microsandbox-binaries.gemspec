# frozen_string_literal: true

require_relative "lib/microsandbox/binaries/version"

platform_name = ENV.fetch("GEM_PLATFORM", nil)
supported_platforms = %w[arm64-darwin x86_64-linux-gnu aarch64-linux-gnu].freeze
unless supported_platforms.include?(platform_name)
  raise Gem::InvalidSpecificationException,
        "microsandbox-binaries.gemspec is build-time-only; GEM_PLATFORM must name a supported " \
        "binaries platform (#{supported_platforms.join(", ")}). Build with " \
        "`rake package[#{Microsandbox::Binaries::VERSION}]`; Gemfile path checkouts do not " \
        "contain a staged runtime payload"
end

Gem::Specification.new do |spec|
  spec.name = "microsandbox-binaries"
  spec.version = Microsandbox::Binaries::VERSION
  spec.authors = ["Super Rad Company"]
  spec.email = ["development@superrad.company"]
  spec.summary = "Platform runtime binaries for the microsandbox Ruby SDK"
  spec.description = "Pure-data platform gem containing the msb runtime and libkrunfw firmware library."
  spec.homepage = "https://github.com/superradcompany/microsandbox"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1"
  # RubyGems only matches the -gnu platform gems on glibc hosts from 3.3.11 onwards.
  spec.required_rubygems_version = Gem::Requirement.new(">= 3.3.11")
  spec.platform = Gem::Platform.new(platform_name)
  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main/sdk/ruby-binaries",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/releases",
    "rubygems_mfa_required" => "true"
  }

  runtime_files = Dir.chdir(__dir__) do
    Dir["libexec/*"].select { |path| File.file?(path) }
  end
  msb_files = runtime_files.select { |path| path == "libexec/msb" }
  firmware_files = runtime_files.select { |path| File.basename(path).start_with?("libkrunfw") }
  unless msb_files.one? && firmware_files.one? && runtime_files.length == 2
    raise Gem::InvalidSpecificationException,
          "staged payload must contain exactly libexec/msb and one versioned libkrunfw library; " \
          "build with the Rake packaging task"
  end

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "README.md", "LICENSE"] + runtime_files
  end
  spec.require_paths = ["lib"]
end
