# frozen_string_literal: true

require "test/unit"

module FilesystemFixture
  module Microsandbox
    class Error < StandardError; end

    class Sandbox
      def fs_read(path)
        GC.start
        "contents of #{path}"
      end
    end
  end
end

FilesystemFixture.module_eval(File.read(File.expand_path("../lib/microsandbox/filesystem.rb", __dir__)))

class FilesystemTest < Test::Unit::TestCase
  def test_live_receiver_remains_available_during_an_operation
    sandbox = FilesystemFixture::Microsandbox::Sandbox.new
    assert_equal "contents of /hello", sandbox.fs.read("/hello")
    assert_same sandbox.fs, sandbox.fs
  end

  def test_idle_helper_does_not_retain_released_receiver
    helper = FilesystemFixture::Microsandbox::Sandbox.new.fs
    GC.start
    error = assert_raise(FilesystemFixture::Microsandbox::Error) { helper.read("/hello") }
    assert_match(/receiver has been released/, error.message)
  end
end
