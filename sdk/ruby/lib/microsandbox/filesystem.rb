# frozen_string_literal: true

require "weakref"

module Microsandbox
  class Filesystem
    def initialize(sandbox)
      @sandbox = WeakRef.new(sandbox)
    end

    def read(path) = sandbox.fs_read(path)
    def write(path, data) = sandbox.fs_write(path, data)
    def mkdir(path) = sandbox.fs_mkdir(path)
    def list(path) = sandbox.fs_list(path)
    def stat(path) = sandbox.fs_stat(path)
    def exists?(path) = sandbox.fs_exists?(path)
    def copy(from, to) = sandbox.fs_copy(from, to)
    def rename(from, to) = sandbox.fs_rename(from, to)
    def remove(path) = sandbox.fs_remove(path)
    def remove_dir(path) = sandbox.fs_remove_dir(path)
    def copy_from_host(host_path, guest_path) = sandbox.fs_copy_from_host(host_path, guest_path)
    def copy_to_host(guest_path, host_path) = sandbox.fs_copy_to_host(guest_path, host_path)

    private

    # Upgrade once for each synchronous native call. The returned receiver stays
    # on the Ruby call stack while I/O runs; an idle helper never owns its run.
    def sandbox
      @sandbox.__getobj__
    rescue WeakRef::RefError
      raise Error, "sandbox receiver has been released; acquire a new Sandbox to begin another operation"
    end
  end

  class Sandbox
    def fs
      @fs ||= Filesystem.new(self)
    end
  end
end
