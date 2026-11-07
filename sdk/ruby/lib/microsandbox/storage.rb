# frozen_string_literal: true

require "json"

module Microsandbox
  StorageCandidate = Data.define(:id, :disk_id, :layers, :virtual_size, :estimated_bytes)
  StorageInspection = Data.define(:status, :reasons, :candidates, :estimated_bytes, :preview_available)
  StorageSandboxDiagnosis = Data.define(:name, :status, :running, :protection_registered, :reason, :inspection, :guest_mounts)
  StorageDiagnosis = Data.define(:home, :sandboxes, :required_runtime_capability)
  StorageRecovery = Data.define(:name, :ready, :originals_retained)

  # Explicit local inspection; never starts, stops, repairs or migrates. SQLite can maintain
  # WAL read-lock sidecars. Candidate views are provisional until locked recovery revalidation.
  def self.diagnose_storage(names: nil, all_sandboxes: false, home: nil)
    if all_sandboxes == !names.nil? || (names && names.empty?)
      raise ArgumentError, "select names or all_sandboxes: true, exclusively"
    end
    unless respond_to?(:_diagnose_storage_json)
      raise NotImplementedError, "storage diagnosis requires an updated native SDK; upgrade or rebuild it"
    end
    scope = all_sandboxes ? "all" : { named: names }
    report = JSON.parse(_diagnose_storage_json(JSON.generate({ home: home }.compact), JSON.generate(scope)), symbolize_names: true)
    report[:sandboxes] = report.fetch(:sandboxes).map do |item|
      if (inspection = item[:inspection])
        inspection[:candidates] = inspection.fetch(:candidates).map { |candidate| StorageCandidate.new(**candidate) }
        item[:inspection] = StorageInspection.new(**{ preview_available: false }.merge(inspection))
      end
      StorageSandboxDiagnosis.new(**{ guest_mounts: {} }.merge(item))
    end
    StorageDiagnosis.new(**report)
  end

  class Sandbox
    # Only a stopped sandbox can recover. Explicit selection can omit later writes and
    # therefore requires acknowledgement; sources remain retained after successful import.
    def self.recover_storage(name, selections: {}, accept_selected_view: false, legacy_writers_stopped: false)
      unless Microsandbox.respond_to?(:_recover_storage_json)
        raise NotImplementedError, "storage recovery requires an updated native SDK; upgrade or rebuild it"
      end
      options = { selections: selections.map { |disk, candidate| { disk_id: disk, candidate_id: candidate } },
                  accept_selected_view: accept_selected_view, legacy_writers_stopped: legacy_writers_stopped }
      result = Microsandbox._recover_storage_json(name, JSON.generate(options))
      StorageRecovery.new(**JSON.parse(result, symbolize_names: true))
    end
  end
end
