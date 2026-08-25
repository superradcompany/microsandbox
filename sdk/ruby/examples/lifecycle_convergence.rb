# frozen_string_literal: true

# Live lifecycle convergence and identity-safety example.

require "json"
require "microsandbox"

name = ENV.fetch("MSB_E2E_NAME", "lifecycle-ruby-#{Process.pid}")
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

cleanup = lambda do
  current = Microsandbox::Sandbox.get(name)
  current.destroy(force: true, timeout: 5.0)
rescue Microsandbox::Error
  nil
end

cleanup.call

begin
  created = measure.call("find_or_create_new") do
    Microsandbox::Sandbox.find_or_create(
      name,
      image: image,
      cpus: 1,
      memory: 256,
      env: { "LIFECYCLE_MARKER" => "original" }
    )
  end
  original_id = created.id

  reused = measure.call("find_or_create_existing") do
    Microsandbox::Sandbox.find_or_create(
      name,
      image: image,
      memory: 768,
      env: { "LIFECYCLE_MARKER" => "ignored" }
    )
  end
  raise "find_or_create changed the persisted identity" unless reused.id == original_id
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
  replacement = Microsandbox::Sandbox.find_or_create(
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
    checks: 10,
    timings_ms: timings,
    result: "pass"
  })}"
rescue StandardError
  cleanup.call
  raise
end
