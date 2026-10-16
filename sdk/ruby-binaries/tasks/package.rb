# frozen_string_literal: true

require "digest"
require "fileutils"
require "open-uri"
require "tmpdir"
require "zlib"
require "rubygems/package"

require_relative "../lib/microsandbox/binaries/version"

module Microsandbox
  module Binaries
    # Build-time support for producing the pure-data platform gems.
    module Package
      ROOT = File.expand_path("..", __dir__)
      DOWNLOADS_DIR = File.join(ROOT, "downloads")
      LIBEXEC_DIR = File.join(ROOT, "libexec")
      PKG_DIR = File.join(ROOT, "pkg")

      REPOSITORY = "superradcompany/microsandbox"
      CHECKSUMS_ASSET = "checksums.sha256"
      PLATFORMS = {
        "arm64-darwin" => {
          target: "darwin-aarch64",
          firmware: /\Alibkrunfw\.\d+\.dylib\z/
        },
        "x86_64-linux-gnu" => {
          target: "linux-x86_64",
          firmware: /\Alibkrunfw\.so\.\d+\.\d+\.\d+\z/
        },
        "aarch64-linux-gnu" => {
          target: "linux-aarch64",
          firmware: /\Alibkrunfw\.so\.\d+\.\d+\.\d+\z/
        }
      }.freeze

      module_function

      def package_all!(version = VERSION)
        PLATFORMS.each_key { |platform| package_platform!(platform, version) }
      end

      def package_platform!(platform, version = VERSION)
        version = validate_version!(version)
        config = PLATFORMS.fetch(platform) do
          raise ArgumentError, "unsupported gem platform: #{platform}"
        end

        release_dir = File.join(DOWNLOADS_DIR, "v#{version}")
        checksums_path = File.join(release_dir, CHECKSUMS_ASSET)
        bundle_name = "microsandbox-#{config.fetch(:target)}.tar.gz"
        bundle_path = File.join(release_dir, bundle_name)
        base_url = "https://github.com/#{REPOSITORY}/releases/download/v#{version}"

        FileUtils.mkdir_p(release_dir)
        download!("#{base_url}/#{CHECKSUMS_ASSET}", checksums_path)
        download!("#{base_url}/#{bundle_name}", bundle_path)

        expected = expected_sha256!(File.read(checksums_path), bundle_name)
        verify_sha256!(bundle_path, expected)

        FileUtils.rm_rf(LIBEXEC_DIR)
        stage_bundle!(bundle_path, config.fetch(:firmware), LIBEXEC_DIR)
        build_gem!(platform, version)
      ensure
        FileUtils.rm_rf(LIBEXEC_DIR)
      end

      def expected_sha256!(checksums, asset)
        matches = checksums.lines.filter_map do |line|
          match = line.chomp.match(/\A([0-9a-fA-F]{64}) [ *](.+)\z/)
          match[1] if match && match[2] == asset
        end
        unless matches.one?
          raise "#{CHECKSUMS_ASSET} must contain exactly one valid entry for #{asset}"
        end

        matches.first.downcase
      end

      def verify_sha256!(path, expected)
        actual = Digest::SHA256.file(path).hexdigest
        return actual if actual == expected

        raise "sha256 mismatch for #{File.basename(path)}: expected #{expected}, got #{actual}; " \
              "run `rake clobber` and retry"
      end

      def stage_bundle!(bundle_path, firmware_pattern, destination)
        payload = {}
        Zlib::GzipReader.open(bundle_path) do |gzip|
          Gem::Package::TarReader.new(gzip) do |tar|
            tar.each do |entry|
              next unless entry.file?

              basename = File.basename(entry.full_name)
              key = if basename == "msb"
                      :msb
                    elsif firmware_pattern.match?(basename)
                      :firmware
                    end
              next unless key
              raise "release bundle contains more than one #{key} artifact" if payload.key?(key)

              payload[key] = [basename, entry.read]
            end
          end
        end

        raise "release bundle is missing msb" unless payload.key?(:msb)
        raise "release bundle must contain exactly one versioned libkrunfw library" unless payload.key?(:firmware)

        FileUtils.mkdir_p(destination)
        write_payload!(File.join(destination, "msb"), payload.fetch(:msb).last, 0o755)
        firmware_name, firmware_data = payload.fetch(:firmware)
        write_payload!(File.join(destination, firmware_name), firmware_data, 0o644)
      end

      def verify_built_gem!(gem_path, platform, version)
        package = Gem::Package.new(gem_path)
        spec = package.spec
        unless spec.name == "microsandbox-binaries" && spec.version.to_s == version && spec.platform.to_s == platform
          raise "built gem identity does not match microsandbox-binaries #{version} #{platform}"
        end

        expected_files = %w[
          LICENSE
          README.md
          lib/microsandbox/binaries.rb
          lib/microsandbox/binaries/version.rb
          libexec/msb
        ]
        firmware_pattern = PLATFORMS.fetch(platform).fetch(:firmware)
        firmware_files = spec.files.select do |path|
          path.start_with?("libexec/libkrunfw") && firmware_pattern.match?(File.basename(path))
        end
        unless firmware_files.one? && spec.files.sort == (expected_files + firmware_files).sort
          raise "built gem contains an unexpected payload: #{spec.files.sort.inspect}"
        end

        Dir.mktmpdir("microsandbox-binaries-gem") do |directory|
          package.extract_files(directory)
          msb = File.join(directory, "libexec", "msb")
          unless File.file?(msb) && File.stat(msb).mode.anybits?(0o111)
            raise "built gem did not preserve the executable bit on libexec/msb"
          end
          firmware = File.join(directory, firmware_files.first)
          raise "built gem is missing #{firmware_files.first}" unless File.file?(firmware)
        end
      end

      def download!(url, destination)
        return destination if File.file?(destination) && File.size(destination).positive?

        temporary = "#{destination}.part-#{Process.pid}"
        URI.open(url, "rb") do |input|
          File.open(temporary, "wb") { |output| IO.copy_stream(input, output) }
        end
        File.rename(temporary, destination)
        destination
      ensure
        FileUtils.rm_f(temporary) if temporary
      end

      def build_gem!(platform, version)
        previous_platform = ENV["GEM_PLATFORM"]
        ENV["GEM_PLATFORM"] = platform
        FileUtils.mkdir_p(PKG_DIR)

        destination = Dir.chdir(ROOT) do
          gemspec_path = File.join(ROOT, "microsandbox-binaries.gemspec")
          # Gem::Specification.load caches by path. A single `rake package`
          # process builds three payloads in sequence, so that cache would
          # reuse the first platform's file list for the later gems.
          spec = eval(File.read(gemspec_path, encoding: "UTF-8"), binding, gemspec_path)
          raise "failed to load microsandbox-binaries.gemspec" unless spec

          destination = File.join(PKG_DIR, spec.file_name)
          FileUtils.rm_f(destination)
          Gem::Package.build(spec, false, true, destination)
          destination
        end
        verify_built_gem!(destination, platform, version)
        puts "built and verified #{destination}"
        destination
      rescue
        FileUtils.rm_f(destination) if destination
        raise
      ensure
        if previous_platform
          ENV["GEM_PLATFORM"] = previous_platform
        else
          ENV.delete("GEM_PLATFORM")
        end
      end

      def validate_version!(version)
        normalized = version.to_s.delete_prefix("v")
        unless normalized == VERSION
          raise ArgumentError, "requested release #{version.inspect} does not match gem version #{VERSION}"
        end

        normalized
      end

      def write_payload!(path, data, mode)
        File.binwrite(path, data)
        FileUtils.chmod(mode, path)
      end
      private_class_method :build_gem!, :download!, :validate_version!, :write_payload!
    end
  end
end
