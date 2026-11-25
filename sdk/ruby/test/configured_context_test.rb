# frozen_string_literal: true

require "tmpdir"
require "json"
require "open3"
require "test/unit"

class ConfiguredContextTest < Test::Unit::TestCase
  def test_retains_configured_metadata_and_authentication
    Dir.mktmpdir("msb-configured-context") do |directory|
      script = <<~'CODE'
        require "microsandbox"
        require "socket"
        require "json"
        server = TCPServer.new("127.0.0.1", 0)
        hits = Queue.new
        worker = Thread.new do
          loop do
            socket = server.accept
            socket.gets
            headers = {}
            while (line = socket.gets) && line != "\r\n"
              key, value = line.split(":", 2)
              headers[key.downcase] = value.strip
            end
            hits << headers["authorization"]
            body = '{"data":[]}'
            socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
            socket.close
          end
        end
        url = "http://127.0.0.1:#{server.addr[1]}"
        select = lambda do |name|
          File.write(ENV.fetch("MSB_CONFIG_PATH"), JSON.generate(active_profile: name, profiles: {
            prod: {kind: "remote", url: url, api_key_ref: "env:MSB_TEST_CONTEXT_KEY"},
            staging: {kind: "remote", url: "http://127.0.0.1:9", api_key_ref: "env:MSB_TEST_CONTEXT_KEY"}
          }))
        end
        begin
          select.call("prod")
          destination = Microsandbox.configured_context
          raise "wrong concrete context" unless destination.is_a?(Microsandbox::RemoteContext)
          info = destination.info
          raise "wrong metadata" unless [info.kind, info.source, info.profile, info.api_url] == [:remote, "active_profile", "prod", url]
          raise "mutable metadata" unless info.frozen? && info.api_url.frozen?
          raise "secret leaked" if info.inspect.include?("captured-secret")
          raise "resolution did I/O" unless hits.empty? && !File.exist?(ENV.fetch("MSB_HOME"))
          select.call("staging")
          ENV["MSB_TEST_CONTEXT_KEY"] = "changed-secret"
          destination.sandboxes.list
          raise "credentials changed" unless hits.pop == "Bearer captured-secret"
          raise "metadata changed" unless destination.info == info
          raise "new selection ignored" unless Microsandbox.configured_context.info.profile == "staging"
          ENV["MSB_PROFILE"] = "prod"
          raise "profile precedence" unless Microsandbox.configured_context.info.source == "MSB_PROFILE"
          ENV["MSB_BACKEND"] = "local"
          local = Microsandbox.configured_context
          raise "local override" unless local.info.kind == :local && local.info.source == "MSB_BACKEND" && local.info.api_url.nil?
          ENV.delete("MSB_BACKEND")
          ENV["MSB_PROFILE"] = "missing"
          begin
            Microsandbox.configured_context
            raise "invalid selection accepted"
          rescue Microsandbox::InvalidConfigError
          end
        ensure
          worker.kill
          worker.join
          server.close
        end
      CODE
      env = ENV.keys.grep(/^MSB_/).to_h { |key| [key, nil] }.merge(
        "MSB_CONFIG_PATH" => File.join(directory, "config.json"),
        "MSB_HOME" => File.join(directory, "home"),
        "MSB_TEST_CONTEXT_KEY" => "captured-secret"
      )
      output, status = Open3.capture2e(env, RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
      assert_predicate(status, :success?, output)
    end
  end
end
