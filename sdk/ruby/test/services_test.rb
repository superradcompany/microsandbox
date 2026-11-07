# frozen_string_literal: true

require "test/unit"
require "socket"
require_relative "../lib/microsandbox"

class ServicesTest < Test::Unit::TestCase
  def setup
    Microsandbox.use_local_backend!
  end

  def test_service_surface_is_registered
    %i[builder create get list].each do |name|
      assert_respond_to Microsandbox::Service, name
    end

    %i[slug url status target created_at updated_at update enable disable remove refresh].each do |name|
      assert_includes Microsandbox::Service.instance_methods, name
    end
  end

  def test_target_exposes_sandbox_and_port
    target = Microsandbox::ServiceTarget.new("web", 8080)

    assert_equal "web", target.sandbox
    assert_equal 8080, target.port
    assert_equal Microsandbox::ServiceTarget.new(sandbox: "web", port: 8080), target
  end

  def test_builder_target_is_chainable
    builder = Microsandbox::Service.builder("ruby-service").target("web", 8080)

    assert_instance_of Microsandbox::ServiceBuilder, builder
  end

  def test_create_accepts_target_keyword
    target = Microsandbox::ServiceTarget.new("web", 8080)

    error = assert_raise(Microsandbox::UnsupportedError) do
      Microsandbox::Service.create("ruby-service", target: target)
    end

    assert_equal "unchanged", error.changed
    assert_equal "service.create", error.operation
  end

  def test_reads_refuse_the_local_backend
    [
      -> { Microsandbox::Service.get("ruby-service") },
      -> { Microsandbox::Service.list }
    ].each do |operation|
      error = assert_raise(Microsandbox::UnsupportedError, &operation)

      assert_match(/cloud backend/, error.hint)
    end
  end

  def test_create_requires_target_keyword
    error = assert_raise(ArgumentError) do
      Microsandbox::Service.create("ruby-service")
    end

    assert_match(/missing keyword: :target/, error.message)
  end

  def test_create_nil_target_has_unchanged_validation_error
    error = assert_raise(Microsandbox::InvalidConfigError) do
      Microsandbox::Service.create("ruby-service", target: nil)
    end

    assert_equal "unchanged", error.changed
  end

  def test_update_requires_target_and_nil_is_unchanged
    service_body = <<~JSON.chomp
      {"slug":"ruby-service","url":"https://ruby-service.example","status":"enabled","target":{"sandbox":"web","port":8080},"created_at":"2026-10-26T10:00:00Z","updated_at":"2026-10-26T10:05:00Z"}
    JSON
    refusal_body = <<~JSON.chomp
      {"error":{"code":"future_refusal","message":"try a newer sdk","details":null}}
    JSON
    paused_body = <<~JSON.chomp
      {"error":{"code":"service_changes_paused","message":"try later","details":null}}
    JSON
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      [
        [201, "Created", service_body, {}],
        [422, "Unprocessable Content", refusal_body, {}],
        [503, "Service Unavailable", paused_body, {"Retry-After" => "5"}]
      ].each do |status, reason, body, headers|
        client = server.accept
        while (line = client.gets)
          break if line == "\r\n"
        end
        response_headers = headers.map { |name, value| "#{name}: #{value}\r\n" }.join
        client.write "HTTP/1.1 #{status} #{reason}\r\n#{response_headers}Content-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
        client.close
      end
    end
    Microsandbox.use_cloud_backend!("test-key", url: "http://127.0.0.1:#{server.local_address.ip_port}")
    target = Microsandbox::ServiceTarget.new("web", 8080)
    service = Microsandbox::Service.create("ruby-service", target: target)

    Microsandbox.use_local_backend!

    omitted = assert_raise(ArgumentError) { service.update }
    assert_match(/missing keyword: :target/, omitted.message)
    invalid = assert_raise(Microsandbox::InvalidConfigError) { service.update(target: nil) }
    assert_equal "unchanged", invalid.changed
    refusal = assert_raise(Microsandbox::ServiceError) { service.update(target: target) }
    assert_equal Microsandbox::ServiceErrorReason::OTHER, refusal.reason
    assert_equal "future_refusal", refusal.raw_code
    assert_equal 422, refusal.raw_status
    assert_equal "try a newer sdk", refusal.raw_message
    paused = assert_raise(Microsandbox::ServiceError) { service.update(target: target) }
    assert_equal Microsandbox::ServiceErrorReason::SERVICE_CHANGES_PAUSED, paused.reason
    assert_equal 5.0, paused.retry_after
  ensure
    server&.close
    thread&.join
  end

  def test_service_error_attributes_default_to_nil
    error = Microsandbox::ServiceError.new("boom")

    %i[slug reason retry_after changed raw_code raw_status raw_message].each do |name|
      assert_nil error.public_send(name), name
    end
    assert_equal "service", error.code
  end

  def test_list_rejects_unknown_keywords
    error = assert_raise(ArgumentError) do
      Microsandbox::Service.list(unknown: true)
    end

    assert_match(/unknown keyword/, error.message)
  end
end
