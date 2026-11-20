# frozen_string_literal: true

require_relative "microsandbox/version"

module Microsandbox
  ServiceTarget = Data.define(:sandbox, :port)
end

# Platform gems stage the binary under lib/microsandbox/<major.minor>/ (one per
# Ruby ABI); source builds produce the flat path. Try the ABI dir first. When
# both misses are plain "no such file", either message will do; but a binary
# that exists and fails to load (e.g. missing libcap-ng.so.0) must win over a
# file miss on the other path, whichever order the two failures arrive in.
begin
  require "microsandbox/#{RUBY_VERSION[/\d+\.\d+/]}/microsandbox"
rescue LoadError => abi_error
  begin
    require "microsandbox/microsandbox"
  rescue LoadError => flat_error
    raise flat_error.message.start_with?("cannot load such file") ? abi_error : flat_error
  end
end

# The base Error is defined natively; the typed subclasses reopen it.
require_relative "microsandbox/errors"

module Microsandbox
  class Service
    def target
      value = _target
      value && ServiceTarget.new(sandbox: value.fetch("sandbox"), port: value.fetch("port"))
    end
  end

  class HttpBuilder
    attr_reader :network_message, :secret_message, :response, :format, :message

    def deny_response(value)
      raise TypeError, "deny_response must be true or false" unless value == true || value == false

      @response = value
      self
    end

    def deny_response_format(value)
      value = value.to_s if value.is_a?(Symbol)
      raise ArgumentError, "deny_response_format must be text or json" unless ["text", "json"].include?(value)

      @format = value
      self
    end

    # Deprecated: legacy text message with {host} substitution. Ignored in JSON mode.
    def deny_message(value)
      raise TypeError, "deny_message must be a String" unless value.is_a?(String)

      @message = value
      self
    end

    def network_deny_message(value)
      raise TypeError, "network_deny_message must be a String" unless value.is_a?(String)

      @network_message = value
      self
    end

    def secret_deny_message(value)
      raise TypeError, "secret_deny_message must be a String" unless value.is_a?(String)

      @secret_message = value
      self
    end
  end

  # Progress is best effort. Always call result to obtain the sandbox or failure.
  class PullSession
    include Enumerable

    def each
      return enum_for(:each) unless block_given?

      while (event = next_event)
        yield event
      end
      self
    end

    def progress = enum_for(:each)
  end

  class SandboxBuilder
    def http
      settings = HttpBuilder.new
      yield settings
      http_config!(settings.response, settings.network_message, settings.secret_message, settings.format, settings.message)
      self
    end

    %i[
      image cpus max_cpus memory max_memory nested_virt workdir shell hostname user
      detached ephemeral max_duration idle_timeout replace root_disk
      disable_network intercept_tls quiet_logs entrypoint init proxy vsock vsock_dgram
    ].each do |name|
      define_method(name) do |*args|
        public_send(:"#{name}!", *args)
        self
      end
    end

    def env(key, value)
      env!(key, value)
      self
    end

    def label(key, value)
      label!(key, value)
      self
    end

    def replace_with_timeout(seconds)
      replace_with_timeout!(seconds)
      self
    end
  end

  class OutboundProxy
    def user_id(value)
      user_id!(value)
      self
    end

    def credentials(username, password)
      credentials!(username, password)
      self
    end
  end
end

require_relative "microsandbox/jobs"

require_relative "microsandbox/storage"

require_relative "microsandbox/lifetime"

require_relative "microsandbox/filesystem"

require_relative "microsandbox/context"
