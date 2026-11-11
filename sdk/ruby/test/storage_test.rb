# frozen_string_literal: true

require "test/unit"
require_relative "../lib/microsandbox/storage"

class StorageTest < Test::Unit::TestCase
  def teardown
    %i[_diagnose_storage_json _recover_storage_json].each do |name|
      Microsandbox.singleton_class.remove_method(name) if Microsandbox.singleton_class.method_defined?(name)
    end
  end

  def test_explicit_scope_partial_results_and_exact_bytes
    payload = { home: "/selected", required_runtime_capability: "protected_guest_state", sandboxes: [
      { name: "app", status: "eligible", running: true, protection_registered: true, reason: nil,
        inspection: { status: "eligible", reasons: [], estimated_bytes: 2**64 - 1,
          candidates: [{ id: "view", disk_id: "root", layers: 1, virtual_size: 2**64 - 1, estimated_bytes: 0 }] } },
      { name: "missing", status: "unavailable", running: false, protection_registered: false, reason: "not_found", inspection: nil }
    ] }
    calls = []
    Microsandbox.define_singleton_method(:_diagnose_storage_json) do |config, scope|
      calls << [JSON.parse(config), JSON.parse(scope)]
      JSON.generate(payload)
    end
    report = Microsandbox.diagnose_storage(names: ["app", "missing"], home: "/selected")
    assert_equal({ "named" => ["app", "missing"] }, calls.first.last)
    assert_equal false, report.sandboxes.first.inspection.preview_available
    assert_equal({}, report.sandboxes.first.guest_mounts)
    assert_equal 2**64 - 1, report.sandboxes.first.inspection.candidates.first.virtual_size
    assert_equal "not_found", report.sandboxes.last.reason
    assert_raise(ArgumentError) { Microsandbox.diagnose_storage }
    assert_raise(ArgumentError) { Microsandbox.diagnose_storage(names: []) }
    assert_raise(ArgumentError) { Microsandbox.diagnose_storage(names: ["app"], all_sandboxes: true) }
    Microsandbox.diagnose_storage(all_sandboxes: true)
    assert_equal "all", calls.last.last
  end

  def test_recovery_preserves_explicit_acknowledgement
    calls = []
    Microsandbox.define_singleton_method(:_recover_storage_json) do |name, options|
      calls << [name, JSON.parse(options)]
      JSON.generate(name: name, ready: true, originals_retained: true)
    end
    result = Microsandbox::Sandbox.recover_storage("app", selections: { "root" => "view" }, accept_selected_view: true, legacy_writers_stopped: true)
    Microsandbox::Sandbox.recover_storage("app")
    assert_false calls.last.last.fetch("legacy_writers_stopped")
    assert_true result.originals_retained
    assert_equal({ "selections" => [{ "disk_id" => "root", "candidate_id" => "view" }], "accept_selected_view" => true, "legacy_writers_stopped" => true }, calls.first.last)
  end
end
