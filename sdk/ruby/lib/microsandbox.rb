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

module Microsandbox
  class SandboxBuilder
    %i[
      image cpus max_cpus memory max_memory workdir shell hostname user
      detached ephemeral max_duration idle_timeout replace root_disk
      disable_network quiet_logs entrypoint init vsock vsock_dgram
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
