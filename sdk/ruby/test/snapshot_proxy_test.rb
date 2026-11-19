# frozen_string_literal: true

require "test/unit"
require "securerandom"
require_relative "../lib/microsandbox"

class SnapshotProxyTest < Test::Unit::TestCase
  def test_destination_proxy_for_group_and_exact_progress
    archive, address = ENV.values_at("MSB_PROXY_ARCHIVE", "MSB_PROXY_ADDRESS")
    omit("requires local proxy fixture, archive and disposable VM home") unless archive && address
    group = Microsandbox::Snapshot.load("ruby-proxy-#{SecureRandom.hex(5)}", [archive]).snapshot
    checkpoint = group.head
    begin
      [false, true].each do |progress|
        child = nil
        name = "ruby-proxy-#{SecureRandom.hex(5)}"
        begin
          proxy = Microsandbox::OutboundProxy.socks5(address)
            .credentials("fixture", Microsandbox::SecretSource.env("MSB_SDK_PROXY_FIXTURE_PASSWORD"))
          # The fixture uses a numeric public test address; Ruby's allowed_hosts
          # helper creates domain rules, not literal-IP rules. Keep default policy.
          options = { name: name, proxy: proxy, ports: [{ host: 0, guest: 18080 }] }
          child = progress ? checkpoint.spawn_sandbox_with_progress(**options).result : group.spawn_sandbox(**options)
          result = child.shell("wget -T 3 -qO- http://198.51.100.10:19090/probe")
          assert_true result.success?
          assert_equal "snapshot-destination-proxy\n", result.stdout
          assert_equal "still-running", child.shell("printf still-running").stdout
        ensure
          child&.stop
          begin
            Microsandbox::Sandbox.get(name).remove
          rescue Microsandbox::SandboxNotFoundError
            nil
          end
        end
      end
    ensure
      group.remove
    end
  end
end
