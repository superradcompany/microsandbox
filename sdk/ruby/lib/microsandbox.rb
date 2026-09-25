# frozen_string_literal: true

require_relative "microsandbox/version"

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

# Core launches a v0.7+ runtime only when it matches the SDK version exactly
# (see its launch contracts), and the companion is not a gemspec dependency, so
# the SDK activates the microsandbox-binaries of its own version and skips any
# other.
skip_companion = lambda do |versions|
  warn "microsandbox #{Microsandbox::VERSION} is ignoring microsandbox-binaries " \
       "#{versions.join(", ")}: the runtime companion must be version " \
       "#{Microsandbox::VERSION}; install microsandbox-binaries #{Microsandbox::VERSION} " \
       "or set MSB_PATH and MSB_LIBKRUNFW_PATH to a compatible runtime"
end

companion_available = true
# A bare require would activate the newest installed companion, which need not
# be this SDK's version. An already activated companion, such as Bundler's
# locked one, is kept and checked below.
if defined?(Gem) && !Gem.loaded_specs.key?("microsandbox-binaries")
  begin
    gem "microsandbox-binaries", Microsandbox::VERSION
  rescue Gem::MissingSpecVersionError => error
    companion_available = false
    skip_companion.call(error.specs.map { |spec| spec.version.to_s }.uniq)
  rescue Gem::LoadError
    # Not installed as a gem, or outside the bundle: the require below still
    # finds a companion on the load path, or fails and is ignored.
  end
end

if companion_available
  begin
    require "microsandbox/binaries"
  rescue LoadError => error
    raise if defined?(Gem) && Gem.loaded_specs.key?("microsandbox-binaries")
    raise unless error.path == "microsandbox/binaries"
  else
    if Microsandbox::Binaries::VERSION == Microsandbox::VERSION
      # Like the Node and Python platform packages, the companion is registered
      # as the packaged fallback: it is used only when MSB_PATH, the explicit
      # setters, config paths and the runtime home all leave the runtime
      # unresolved. Core finds its libkrunfw beside the registered msb.
      msb_path = Microsandbox::Binaries.msb_path
      # Validates the bundled firmware, so a broken companion raises here
      # instead of surfacing later as an incomplete runtime.
      Microsandbox::Binaries.libkrunfw_path
      Microsandbox.set_packaged_msb_path(msb_path)
    else
      skip_companion.call([Microsandbox::Binaries::VERSION])
    end
  end
end

module Microsandbox
  class SandboxBuilder
    %i[
      image cpus max_cpus memory max_memory workdir shell hostname user
      detached ephemeral max_duration idle_timeout replace root_disk
      disable_network quiet_logs entrypoint init proxy vsock vsock_dgram
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

  class Filesystem
    def initialize(sandbox)
      @sandbox = sandbox
    end

    def read(path) = @sandbox.fs_read(path)
    def write(path, data) = @sandbox.fs_write(path, data)
    def mkdir(path) = @sandbox.fs_mkdir(path)
    def list(path) = @sandbox.fs_list(path)
    def stat(path) = @sandbox.fs_stat(path)
    def exists?(path) = @sandbox.fs_exists?(path)
    def copy(from, to) = @sandbox.fs_copy(from, to)
    def rename(from, to) = @sandbox.fs_rename(from, to)
    def remove(path) = @sandbox.fs_remove(path)
    def remove_dir(path) = @sandbox.fs_remove_dir(path)
    def copy_from_host(host_path, guest_path) = @sandbox.fs_copy_from_host(host_path, guest_path)
    def copy_to_host(guest_path, host_path) = @sandbox.fs_copy_to_host(guest_path, host_path)
  end

  class Sandbox
    def self.with(name, **options)
      sandbox = create(name, **options)
      return sandbox unless block_given?

      begin
        yield sandbox
      ensure
        primary_error = $!
        begin
          sandbox.stop
        rescue StandardError
          raise if primary_error.nil?
        end
      end
    end

    def fs
      @fs ||= Filesystem.new(self)
    end
  end
end
