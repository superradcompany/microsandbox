# frozen_string_literal: true

require "json"

module Microsandbox
  # Values describe captured configuration and never contain credentials.
  ContextInfo = Data.define(:kind, :source, :profile, :api_url)

  class Context
    def info
      value = JSON.parse(__info_json)
      ContextInfo.new(kind: value.fetch("kind").to_sym, source: value.fetch("source").freeze,
                     profile: value["profile"]&.freeze, api_url: value["api_url"]&.freeze)
    end
  end

  class LocalContext < Context
    def self.new(home: nil, config_path: nil)
      # Normalize Pathname-like inputs, without resolving or canonicalizing them here.
      __from_json(JSON.generate(kind: "local", home: (home.respond_to?(:to_path) ? home.to_path : home), configPath: (config_path.respond_to?(:to_path) ? config_path.to_path : config_path)))
    end
  end

  class RemoteContext < Context
    def self.new(url: nil, api_key: nil, profile: nil, request_timeout_ms: nil, user_agent: nil, compute_type: nil)
      unless request_timeout_ms.nil? || (request_timeout_ms.is_a?(Integer) && request_timeout_ms.between?(0, (1 << 64) - 1))
        raise ArgumentError, "request_timeout_ms must be a non-negative 64-bit integer"
      end
      options = {kind: "remote", url: url, apiKey: api_key, profile: profile,
                 requestTimeoutMs: request_timeout_ms, userAgent: user_agent}
      options[:computeType] = compute_type unless compute_type.nil?
      __from_json(JSON.generate(options))
    end

    # Return an independent destination. Nil retains the captured value; profiles,
    # environment and configuration files are never resolved again.
    def with(url: nil, api_key: nil, request_timeout_ms: nil, user_agent: nil, compute_type: nil)
      unless request_timeout_ms.nil? || (request_timeout_ms.is_a?(Integer) && request_timeout_ms.between?(0, (1 << 64) - 1))
        raise ArgumentError, "request_timeout_ms must be a non-negative 64-bit integer"
      end
      options = {url: url, apiKey: api_key, requestTimeoutMs: request_timeout_ms, userAgent: user_agent}
      options[:computeType] = compute_type unless compute_type.nil?
      self.class.__derive_from_json(self, JSON.generate(options))
    end

    # Explicit endpoint selection shares the normal constructor's validation.
    def self.with_url(url, api_key, request_timeout_ms: nil, user_agent: nil, compute_type: nil)
      new(url: url, api_key: api_key, request_timeout_ms: request_timeout_ms, user_agent: user_agent, compute_type: compute_type)
    end

    def self.from_profile(name)
      new(profile: name)
    end

    def self.from_env
      new
    end
  end
end

module Microsandbox
  class Checkpoint
    def self.group_head(group)
      local.group_head(group)
    end

    def self.set_group_head(group, id)
      local.set_group_head(group, id)
    end
  end

  # Select before creation/lookup; returned collections retain their context.
  { Sandbox => :sandboxes, Volume => :volumes, Snapshot => :snapshots, Checkpoint => :checkpoints }.each do |resource, collection|
    resource.define_singleton_method(:local) { LocalContext.new.public_send(collection) }
    resource.define_singleton_method(:remote) { RemoteContext.from_env.public_send(collection) }
  end
end
