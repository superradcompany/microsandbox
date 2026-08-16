# frozen_string_literal: true

require "test/unit"
require "securerandom"
require_relative "../lib/microsandbox"

class MicrosandboxIntegrationTest < Test::Unit::TestCase
  IMAGE = ENV.fetch("MSB_RUBY_TEST_IMAGE", "alpine")

  def setup
    omit("set MSB_RUBY_INTEGRATION=1 on a KVM/WHP/Apple Virtualization host") unless ENV["MSB_RUBY_INTEGRATION"] == "1"
    @names = []
  end

  def teardown
    @names&.each do |name|
      begin
        handle = Microsandbox::Sandbox.get(name)
        handle.stop if handle.status == "running"
        handle.remove
      rescue Microsandbox::Error
        nil
      end
    end
  end

  def test_network_none_blocks_egress
    sandbox = create_sandbox("net-none", network: :none)
    output = sandbox.shell("wget -qO- --timeout=5 https://example.com >/dev/null 2>&1")

    assert_false output.success?
  ensure
    sandbox&.stop
  end

  def test_network_allowlist_allows_one_host_and_denies_another
    sandbox = create_sandbox(
      "net-allowlist",
      network: { allowed_hosts: ["example.com"], allowed_ports: [443] }
    )

    allowed = sandbox.shell("wget -qO- --timeout=10 https://example.com >/dev/null 2>&1")
    denied = sandbox.shell("wget -qO- --timeout=5 https://www.iana.org >/dev/null 2>&1")

    assert_true allowed.success?
    assert_false denied.success?
  ensure
    sandbox&.stop
  end

  def test_tls_proxy_substitutes_secret_without_exposing_plaintext_in_guest
    secret = "ruby-secret-#{SecureRandom.hex(8)}"
    sandbox = create_sandbox(
      "secret",
      network: { allowed_hosts: ["httpbingo.org"], allowed_ports: [443] },
      secrets: [{ env: "API_KEY", value: secret, allowed_host: "httpbingo.org" }]
    )

    guest_env = sandbox.shell('printf "%s" "$API_KEY"')
    response = sandbox.shell(
      'for attempt in 1 2 3; do wget -qO- --timeout=15 --header="Authorization: Bearer $API_KEY" https://httpbingo.org/headers && break; sleep 1; done'
    )

    assert_not_include guest_env.stdout, secret
    assert_include response.stdout, secret
    assert_not_include response.stdout, "MSB_API_KEY"
  ensure
    sandbox&.stop
  end

  def test_gc_stops_owned_sandbox_and_detach_keeps_it_running
    owned_name = unique_name("gc-owned")
    @names << owned_name
    owned = Microsandbox::Sandbox.create(owned_name, image: IMAGE, cpus: 1, memory: 256, replace: true)
    owned = nil

    GC.start(full_mark: true, immediate_sweep: true)
    assert_eventually("owned sandbox to stop after GC") do
      Microsandbox::Sandbox.get(owned_name).refresh.status != "running"
    end

    detached_name = unique_name("gc-detached")
    @names << detached_name
    detached = Microsandbox::Sandbox.create(detached_name, image: IMAGE, cpus: 1, memory: 256, replace: true)
    detached.detach
    detached = nil
    GC.start(full_mark: true, immediate_sweep: true)

    assert_equal "running", Microsandbox::Sandbox.get(detached_name).refresh.status
  end

  def test_blocking_native_calls_release_the_gvl
    sandbox = create_sandbox("gvl")
    stop_worker = false
    ticks = 0
    worker = Thread.new do
      until stop_worker
        ticks += 1
        Thread.pass
      end
    end

    sandbox.shell("sleep 1")
    stop_worker = true
    worker.join

    assert_operator ticks, :>, 100
  ensure
    stop_worker = true
    worker&.join
    sandbox&.stop
  end

  def test_ssh_exec_accepts_inactivity_timeout
    sandbox = create_sandbox("ssh-timeout")

    output = sandbox.ssh_exec("printf ruby-ssh", inactivity_timeout: 0)

    assert_equal "ruby-ssh", output.fetch("stdout")
    assert_true output.fetch("success")
  ensure
    sandbox&.stop
  end

  def test_assert_eventually_enforces_timeout
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert_raise(Test::Unit::AssertionFailedError) do
      assert_eventually("condition that remains false", timeout: 0.02) { false }
    end

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
    assert_operator elapsed, :<, 1
  end

  private

  def create_sandbox(label, **options)
    name = unique_name(label)
    @names << name
    Microsandbox::Sandbox.create(
      name,
      image: IMAGE,
      cpus: 1,
      memory: 256,
      replace: true,
      **options
    )
  end

  def unique_name(label)
    "ruby-#{label}-#{Process.pid}-#{SecureRandom.hex(4)}"
  end

  def assert_eventually(message, timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      begin
        value = yield
        return assert_true(value) if value
      rescue Microsandbox::Error
        return assert_true(true)
      end

      break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.1
    end

    flunk("timed out waiting for #{message}")
  end
end
