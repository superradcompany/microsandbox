# frozen_string_literal: true

# Live lifecycle convergence and identity-safety example.

require "json"
require "microsandbox"

name = ENV.fetch("MSB_E2E_NAME", "lifecycle-ruby-#{Process.pid}")
race_name = "#{name}-race"
image = ENV.fetch("MSB_E2E_IMAGE", "alpine:3.19")
platform = ENV.fetch("MSB_E2E_PLATFORM", RUBY_PLATFORM)
timings = {}
total = Process.clock_gettime(Process::CLOCK_MONOTONIC)

measure = lambda do |label, &operation|
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  value = operation.call
  timings[label] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1_000
  value
end

read_marker = lambda do |sandbox|
  output = sandbox.shell('printf \'%s\' "$LIFECYCLE_MARKER"')
  raise "marker exec failed" unless output.success?

  output.stdout
end

cleanup = lambda do |target = name|
  current = Microsandbox::Sandbox.get(target)
  current.destroy(force: true, timeout: 5.0)
rescue Microsandbox::Error
  nil
end

cleanup.call
cleanup.call(race_name)

run_concurrency_checks = lambda do
  candidates = ["candidate-0", "candidate-1", "candidate-2", "candidate-3"]
  raced = measure.call("concurrent_connect_or_create") do
    candidates.map do |marker|
      Thread.new do
        Microsandbox::Sandbox.connect_or_create(
          race_name,
          image: image,
          cpus: 1,
          memory: 256,
          env: { "LIFECYCLE_MARKER" => marker }
        )
      end
    end.map(&:value)
  end
  race_id = raced.first.id
  raise "concurrent connect_or_create callers selected different identities" unless raced.all? { |sandbox| sandbox.id == race_id }

  marker = read_marker.call(raced.first)
  raise "concurrent creation persisted unexpected marker #{marker.inspect}" unless candidates.include?(marker)

  raced.first.stop
  handles = candidates.map { Microsandbox::Sandbox.get(race_name) }
  connected = measure.call("concurrent_connect_or_start") do
    handles.map { |handle| Thread.new { handle.connect_or_start } }.map(&:value)
  end
  raise "concurrent connect_or_start callers selected different identities" unless connected.all? { |sandbox| sandbox.id == race_id }
  raise "start race lost persisted configuration" unless read_marker.call(connected.first) == marker

  connected.first.stop
  detached = measure.call("connect_or_start_detached") do
    handles.first.connect_or_start(detached: true)
  end
  unless detached.id == race_id && !detached.owns_lifecycle?
    raise "detached connect_or_start changed identity or took lifecycle ownership"
  end

  forced = measure.call("restart_force") do
    detached.restart(force: true, timeout: 5.0)
  end
  unless forced.id == race_id && forced.owns_lifecycle?
    raise "forced restart changed identity or failed to return an attached handle"
  end
  raise "forced restart lost persisted configuration" unless read_marker.call(forced) == marker

  detached_restart = measure.call("restart_detached_timeout") do
    forced.restart(timeout: 3.0, detached: true)
  end
  unless detached_restart.id == race_id && !detached_restart.owns_lifecycle?
    raise "detached restart changed identity or took lifecycle ownership"
  end
  raise "detached restart lost persisted configuration" unless read_marker.call(detached_restart) == marker

  measure.call("destroy_force_timeout") do
    detached_restart.destroy(force: true, timeout: 5.0)
  end
end

begin
  run_concurrency_checks.call
  created = measure.call("connect_or_create_new") do
    Microsandbox::Sandbox.connect_or_create(
      name,
      image: image,
      cpus: 1,
      memory: 256,
      env: { "LIFECYCLE_MARKER" => "original" }
    )
  end
  original_id = created.id

  reused = measure.call("connect_or_create_existing") do
    Microsandbox::Sandbox.connect_or_create(
      name,
      image: image,
      memory: 768,
      env: { "LIFECYCLE_MARKER" => "ignored" }
    )
  end
  raise "connect_or_create changed the persisted identity" unless reused.id == original_id
  raise "existing configuration did not win" unless read_marker.call(reused) == "original"

  handle = Microsandbox::Sandbox.get(name)
  connected = measure.call("connect_or_start") { handle.connect_or_start }
  raise "connect_or_start changed the persisted identity" unless connected.id == original_id

  measure.call("wait_for_running") { connected.wait_for_status("running") }
  measure.call("exec") do
    raise "exec observed the wrong configuration" unless read_marker.call(connected) == "original"
  end

  restarted = measure.call("restart") { connected.restart }
  raise "restart changed the persisted identity" unless restarted.id == original_id
  raise "restart lost persisted configuration" unless read_marker.call(restarted) == "original"

  stale = Microsandbox::Sandbox.get(name)
  measure.call("destroy_original") { restarted.destroy }
  replacement = Microsandbox::Sandbox.connect_or_create(
    name,
    image: image,
    cpus: 1,
    memory: 256,
    env: { "LIFECYCLE_MARKER" => "replacement" }
  )
  raise "replacement reused the destroyed identity" if replacement.id == original_id

  measure.call("stale_identity_rejection") do
    begin
      stale.destroy
      raise "stale receiver acted on the replacement"
    rescue Microsandbox::Error => e
      raise unless e.message.include?("was replaced")
    end
  end
  raise "stale receiver harmed replacement" unless read_marker.call(replacement) == "replacement"
  measure.call("destroy_replacement") { replacement.destroy }
  timings["total"] = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - total) * 1_000

  puts "MSB_LIFECYCLE_METRICS #{JSON.generate({
    sdk: "ruby",
    platform: platform,
    sandbox: name,
    identity: original_id,
    checks: 16,
    timings_ms: timings,
    result: "pass"
  })}"
rescue StandardError
  cleanup.call
  cleanup.call(race_name)
  raise
end
