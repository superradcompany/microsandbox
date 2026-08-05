# frozen_string_literal: true

require "microsandbox/microsandbox"

module Microsandbox
  class SandboxBuilder
    %i[
      image cpus max_cpus memory max_memory workdir shell hostname user
      detached ephemeral max_duration idle_timeout replace root_disk
      disable_network quiet_logs entrypoint init
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

  class Sandbox
    def self.with(name, **options)
      sandbox = create(name, **options)
      return sandbox unless block_given?

      begin
        yield sandbox
      ensure
        sandbox.stop
      end
    end
  end
end
