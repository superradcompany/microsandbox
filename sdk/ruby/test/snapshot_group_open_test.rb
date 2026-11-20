# frozen_string_literal: true

require "test/unit"
require "tmpdir"
require "fileutils"
require "open3"
require "rbconfig"
require_relative "../lib/microsandbox"

class SnapshotGroupOpenTest < Test::Unit::TestCase
  def test_external_history_does_not_select_same_named_default
    unless ENV["MSB_RUBY_GROUP_OPEN_WORKER"] == "1"
      Dir.mktmpdir("msb-group-open-ruby-") do |root|
        env = { "MSB_BACKEND" => "local", "MSB_HOME" => File.join(root, "home"), "MSB_CONFIG_PATH" => File.join(root, "absent.json"), "MSB_RUBY_GROUP_OPEN_WORKER" => "1" }
        output, status = Open3.capture2e(env, RbConfig.ruby, *$LOAD_PATH.flat_map { |path| ["-I", path] }, __FILE__, "--name", method_name)
        assert_predicate status, :success?, output
      end
      return
    end

    root = File.dirname(ENV.fetch("MSB_HOME"))
    external = File.join(root, "external", "history")
    named = File.join(ENV.fetch("MSB_HOME"), "snapshots", "history")
    metadata = '{"schema":"microsandbox.snapshot-group/1","head":null}'
    [external, named].each do |path|
      FileUtils.mkdir_p(path)
      File.write(File.join(path, "group.json"), metadata)
    end
    history = Dir.chdir(root) { Microsandbox::Snapshot.open("./external/history") }
    assert_equal "history", history.name
    assert_equal File.realpath(external), history.info["path"]
    assert_nil history.head
    assert_equal [], history.checkpoints
    assert_raise_kind_of(Microsandbox::Error) { Microsandbox::Snapshot.open(File.join(root, "missing")) }
    assert_equal File.realpath(named), Microsandbox::Snapshot.get("history").info["path"]
    history.remove
    assert_false File.exist?(external)
    assert_equal metadata, File.read(File.join(named, "group.json"))
  end
end
