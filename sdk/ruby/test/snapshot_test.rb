# frozen_string_literal: true

require "open3"
require "rbconfig"
require "test/unit"
require "tmpdir"

class SnapshotTest < Test::Unit::TestCase
  def test_unified_snapshot_loads_metadata_and_retains_identity
    Dir.mktmpdir("msb-ruby-snapshot-") do |home|
      env = ENV.keys.grep(/^MSB_/).to_h { |key| [key, nil] }
      env["MSB_HOME"] = home
      library = File.expand_path("../lib/microsandbox", __dir__)
      script = <<~RUBY
        require #{library.inspect}
        require "json"
        require "fileutils"
        raise "old resource export" if Microsandbox.const_defined?(:SnapshotHandle, false)
        path = File.join(ENV.fetch("MSB_HOME"), "snapshots", "fixture")
        FileUtils.mkdir_p(path)
        descriptor = File.join(path, "snapshot.json")
        bytes = JSON.generate({
          schema: 1, artifact: "snapshot", scope: "disk", created_at: "2026-05-01T12:00:00Z",
          parent: nil, image: {ref: "alpine:3.21", manifest_digest: "sha256:" + "a" * 64},
          source_sandbox: "fixture", labels: {},
          state: {kind: "file", format: "raw", fstype: "ext4", upper: {file: "disk.ext4", size_bytes: 4, integrity: nil}},
          extensions: {}, requires: []
        })
        File.write(descriptor, bytes)
        File.write(File.join(path, "disk.ext4"), "data")
        opened = Microsandbox::Checkpoint.open(path)
        File.unlink(descriptor)
        fetched = Microsandbox::Checkpoint.get(opened.id)
        listed = Microsandbox::Checkpoint.list.fetch(0)
        [opened, fetched, listed].each do |snapshot|
          raise "different type" unless snapshot.instance_of?(Microsandbox::Checkpoint)
          raise "different identity" unless snapshot.id == opened.id
          failed = false
          begin
            snapshot.manifest
          rescue Microsandbox::Error
            failed = true
          end
          raise "returned stale descriptor" unless failed
        end
        File.write(descriptor, bytes)
        [opened, fetched, listed].each do |snapshot|
          raise "wrong state kind" unless snapshot.state_kind == :file
          raise "wrong reference kind" unless snapshot.reference_kind.is_a?(Symbol)
          raise "wrong state" unless snapshot.state.fetch("kind") == "file"
          raise "wrong identity" unless snapshot.manifest.fetch("snapshot_id") == snapshot.id
        end
        listed.destroy(false)
        raise "artifact remains" if File.exist?(path)
      RUBY
      output, status = Open3.capture2e(env, RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
      assert_predicate status, :success?, output
    end
  end
end
