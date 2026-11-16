# frozen_string_literal: true

require "json"

module Microsandbox
  class LocalContext < Context
    def self.new(home: nil, config_path: nil)
      # Normalize Pathname-like inputs, without resolving or canonicalizing them here.
      __from_json(JSON.generate(kind: "local", home: (home.respond_to?(:to_path) ? home.to_path : home), configPath: (config_path.respond_to?(:to_path) ? config_path.to_path : config_path)))
    end
  end

  class RemoteContext < Context
    def self.new(url: nil, api_key: nil, profile: nil, request_timeout_ms: nil, user_agent: nil)
      unless request_timeout_ms.nil? || (request_timeout_ms.is_a?(Integer) && request_timeout_ms.between?(0, (1 << 64) - 1))
        raise ArgumentError, "request_timeout_ms must be a non-negative 64-bit integer"
      end
      __from_json(JSON.generate(kind: "remote", url: url, apiKey: api_key, profile: profile,
                               requestTimeoutMs: request_timeout_ms, userAgent: user_agent))
    end

    def self.from_profile(name)
      new(profile: name)
    end

    def self.from_env
      new(url: ENV["MSB_API_URL"], api_key: ENV["MSB_API_KEY"])
    end
  end
end
