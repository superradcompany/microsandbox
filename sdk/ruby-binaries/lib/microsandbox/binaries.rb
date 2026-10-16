# frozen_string_literal: true

require "rubygems"

require_relative "binaries/version"

module Microsandbox
  # Paths to the runtime files carried by the platform-specific companion gem.
  module Binaries
    GEM_NAME = "microsandbox-binaries"

    # Raised when the activated gem does not carry a usable payload for the
    # current host platform.
    class PlatformError < StandardError; end

    class << self
      # Returns the absolute path to the bundled `msb` executable.
      def msb_path
        ensure_matching_platform!
        path = File.join(package_root, "libexec", "msb")

        unless File.file?(path)
          raise PlatformError,
                "#{GEM_NAME} for #{current_platform} is missing its bundled msb executable"
        end

        path
      end

      # Returns the absolute path to the bundled, versioned libkrunfw library.
      def libkrunfw_path
        ensure_matching_platform!
        matches = Dir.glob(File.join(package_root, "libexec", libkrunfw_pattern)).select { |path| File.file?(path) }

        unless matches.one?
          raise PlatformError,
                "#{GEM_NAME} for #{current_platform} must contain exactly one versioned libkrunfw library"
        end

        matches.first
      end

      private

      def current_platform
        Gem::Platform.local
      end

      def ensure_matching_platform!
        loaded_spec = Gem.loaded_specs[GEM_NAME]
        unless loaded_spec
          raise PlatformError,
                "#{GEM_NAME} is not activated through RubyGems; " \
                "install the matching platform gem before requiring microsandbox/binaries"
        end

        gem_platform = loaded_spec.platform
        return if gem_platform === current_platform

        raise PlatformError,
              "#{GEM_NAME} platform #{gem_platform} does not match current platform #{current_platform}"
      end

      def libkrunfw_pattern
        case current_platform.os
        when "darwin" then "libkrunfw.*.dylib"
        when "linux" then "libkrunfw.so.*.*.*"
        else
          raise PlatformError,
                "#{GEM_NAME} does not support current platform #{current_platform}"
        end
      end

      # Every path is built from this absolute root, so callers never need to
      # expand what they receive.
      def package_root
        File.expand_path("../..", __dir__)
      end
    end
  end
end
