# frozen_string_literal: true

require "fileutils"
require "open3"
require "rbconfig"
require "test/unit"
require "tmpdir"

class VolumeTest < Test::Unit::TestCase
  def test_unified_volume_keeps_created_identity_and_rejects_replacements
    Dir.mktmpdir("msb-ruby-volume-") do |home|
      # A subprocess isolates native configuration from other tests and the user's home.
      env = ENV.keys.grep(/^MSB_/).to_h { |key| [key, nil] }
      env["MSB_HOME"] = home
      library = File.expand_path("../lib/microsandbox", __dir__)
      script = <<~RUBY
        require #{library.inspect}
        raise "old resource export" if Microsandbox.const_defined?(:VolumeHandle, false)
        created = Microsandbox::Volume.builder("cache").label("team", "sdk").create
        fetched = Microsandbox::Volume.get("cache")
        listed = Microsandbox::Volume.list.fetch(0)
        [created, fetched, listed].each do |volume|
          raise "different type" unless volume.instance_of?(Microsandbox::Volume)
          raise "different identity" unless volume.id == created.id
          raise "inconsistent kind" unless volume.kind == :dir && volume.info.fetch("kind") == :dir
          raise "lost metadata" unless volume.info.fetch("labels") == {"team" => "sdk"}
        end
        disk = Microsandbox::Volume.builder("scratch").disk.size(256).create
        raise "wrong disk kind" unless disk.kind == :disk && disk.info.fetch("kind") == :disk
        disk.destroy
        listed.destroy
        replacement = Microsandbox::Volume.builder("cache").create
        raise "reused identity" if created.id == replacement.id
        begin
          created.destroy
          raise "deleted replacement"
        rescue Microsandbox::VolumeNotFoundError
        end
        raise "replacement disappeared" unless Microsandbox::Volume.get("cache").id == replacement.id
        Microsandbox::Volume.remove("cache")
        raise "not removed" unless Microsandbox::Volume.list.empty?
      RUBY
      output, status = Open3.capture2e(env, RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
      assert_predicate status, :success?, output
    end
  end
end
