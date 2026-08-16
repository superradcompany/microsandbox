# frozen_string_literal: true

require_relative "lib/microsandbox/version"

Gem::Specification.new do |spec|
  spec.name = "microsandbox"
  spec.version = Microsandbox::VERSION
  spec.authors = ["Super Rad Company"]
  spec.email = ["development@superrad.company"]
  spec.summary = "Ruby bindings for fast, local microVM sandboxes"
  spec.description = "Magnus-based Ruby bindings for the microsandbox Rust SDK."
  spec.homepage = "https://github.com/superradcompany/microsandbox"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main/sdk/ruby",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/releases",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "ext/**/*", "Rakefile", "microsandbox.gemspec", "README.md", "LICENSE"]
      .reject { |path| path == "ext/microsandbox/target" || path.start_with?("ext/microsandbox/target/") }
  end
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/microsandbox/extconf.rb"]
  # Required while installing the source gem: extconf.rb loads rb_sys/mkmf.
  spec.add_runtime_dependency "rb_sys", "~> 0.9"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "test-unit", "~> 3.6"
end
