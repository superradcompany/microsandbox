# frozen_string_literal: true

require "test/unit"
require_relative "../lib/microsandbox"

class SnapshotPullPolicyTest < Test::Unit::TestCase
  def test_cached_and_revalidated_snapshot_spawn
    archive = ENV["MSB_PULL_ARCHIVE"]
    omit("requires a snapshot archive and disposable VM home") unless archive
    group = Microsandbox::Snapshot.load("ruby-pull-history", [archive]).snapshot
    checkpoint = group.head
    begin
      %w[never if-missing always].each do |policy|
        child = nil
        name = "ruby-pull-#{policy}"
        begin
          options = { name: name, pull_policy: policy, ports: [{ host: 0, guest: 18080 }] }
          child = policy == "never" ? group.spawn_sandbox(**options) : checkpoint.spawn_sandbox_with_progress(**options).result
          result = child.shell("printf policy-alive")
          assert_true result.success?
          assert_equal "policy-alive", result.stdout
        ensure
          if child
            child.stop
            Microsandbox::Sandbox.get(name).remove
          end
        end
      end
    ensure
      group.remove
    end
  end
end
