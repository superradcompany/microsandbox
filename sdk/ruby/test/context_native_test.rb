# frozen_string_literal: true

# Run with the Ruby ABI used to build the extension and MSB_CONTEXT_RUBY_LIBRARY.
require "tmpdir"
require "fileutils"
require "json"
require "socket"
require "open3"
require "test/unit"

class ContextNativeTest < Test::Unit::TestCase
  def test_retained_contexts_and_resources
    library = ENV["MSB_CONTEXT_RUBY_LIBRARY"]
    omit("set MSB_CONTEXT_RUBY_LIBRARY to the rebuilt extension") unless library

    Dir.mktmpdir("msb-ruby-context") do |directory|
      package = File.join(directory, "microsandbox")
      FileUtils.cp_r(File.expand_path("../lib/microsandbox", __dir__), package)
      FileUtils.cp(File.expand_path("../lib/microsandbox.rb", __dir__), directory)
      FileUtils.rm_f(File.join(package, "microsandbox.bundle"))
      File.symlink(File.expand_path(library), File.join(package, "microsandbox.bundle"))
      script = <<~'CODE'
        require "microsandbox"
        require "socket"
        require "json"
        servers = []
        workers = []
        creates = []
        provider = lambda do |id|
          server = TCPServer.new("127.0.0.1", 0)
          servers << server
          workers << Thread.new do
            loop do
              socket = server.accept
              request = socket.gets
              headers = {}
              while (line = socket.gets) && line != "\r\n"
                key, value = line.split(":", 2)
                headers[key.downcase] = value.strip
              end
              raise "wrong credentials" unless headers["authorization"] == "Bearer key-#{id}"
              if request.start_with?("POST ")
                body = JSON.parse(socket.read(headers.fetch("content-length").to_i))
                creates << body.fetch("compute").fetch("type")
                socket.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                socket.close
                next
              end
              raise "unexpected mutation" unless request.start_with?("GET ")
              observation = {id: id, name: "task", slug: "task", org_id: "org", status: "running", ephemeral: false, created_at: "2026-11-15T00:00:00Z"}
              path = request.split[1].split("?")[0]
              body = JSON.generate(path == "/v1/sandboxes" ? {data: [observation]} : observation)
              socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
              socket.close
            end
          end
          Microsandbox::RemoteContext.with_url("http://127.0.0.1:#{server.addr[1]}", "key-#{id}")
        end
        begin
          raise "wrong hosted type" unless Microsandbox::RemoteContext.new(api_key: "hosted-key").is_a?(Microsandbox::RemoteContext)
          [-> { Microsandbox::RemoteContext.new(api_key: "") },
           -> { Microsandbox::RemoteContext.with_url("", "key") },
           -> { Microsandbox::RemoteContext.with_url("http://localhost", "key", request_timeout_ms: -1) }].each do |construct|
            rejected = false
            begin
              construct.call
            rescue StandardError
              rejected = true
            end
            raise "invalid remote constructor accepted" unless rejected
          end
          a, b = provider.call("a"), provider.call("b")
          a = a.with(compute_type: "shared")
          [a.with, a.with(compute_type: "standard")].each do |selected|
            begin
              selected.sandboxes.create("task", image: "python")
              raise "fixture should deny creation"
            rescue Microsandbox::Error => error
              raise error unless error.message.include?("403")
            end
          end
          raise "compute options lost" unless creates == ["shared", "standard"]

          raise "wrong concrete type" unless a.is_a?(Microsandbox::RemoteContext)
          raise "wrong local type" unless Microsandbox::LocalContext.new.is_a?(Microsandbox::LocalContext)
          [Microsandbox::Sandbox, Microsandbox::Volume, Microsandbox::Checkpoint].each do |resource|
            rejected = false
            begin
              resource.remote
            rescue StandardError
              rejected = true
            end
            raise "missing credentials accepted" unless rejected
          end
          ENV["MSB_API_URL"] = "http://127.0.0.1:#{servers.first.addr[1]}"
          ENV["MSB_API_KEY"] = "key-a"
          ENV["MSB_BACKEND"] = "local"
          remote = Microsandbox::RemoteContext
          url_a = ENV.fetch("MSB_API_URL")
          raise "missing env defaults" unless remote.new(compute_type: "shared").sandboxes.get("task").id == "cloud:a"
          ENV["MSB_API_KEY"] = "wrong"
          raise "explicit key lost" unless remote.new(api_key: "key-a").sandboxes.get("task").id == "cloud:a"
          ENV["MSB_API_KEY"] = "key-a"
          ENV["MSB_API_URL"] = "http://127.0.0.1:#{servers.last.addr[1]}"
          raise "explicit URL lost" unless remote.new(url: url_a).sandboxes.get("task").id == "cloud:a"
          ENV["MSB_API_URL"] = url_a
          collection = Microsandbox::Sandbox.remote
          [Microsandbox::Sandbox, Microsandbox::Volume, Microsandbox::Checkpoint].each do |resource|
            raise "remote selector ignored" unless resource.remote.context.kind == :remote
          end
          ENV["MSB_BACKEND"] = "remote"
          raise "configured lookup missed remote" unless Microsandbox::Sandbox.get("task").id == collection.get("task").id
          [Microsandbox::Sandbox, Microsandbox::Volume, Microsandbox::Checkpoint].each do |resource|
            raise "local selector ignored" unless resource.local.context.kind == :local
          end
          ENV["MSB_API_URL"] = "http://127.0.0.1:#{servers.last.addr[1]}"
          ENV["MSB_API_KEY"] = "key-b"
          raise "unchanged derivation lost settings" unless a.with.sandboxes.get("task").id == collection.get("task").id
          [{api_key: ""}, {url: ""}, {request_timeout_ms: -1}].each do |overrides|
            rejected = false
            begin
              a.with(**overrides)
            rescue StandardError
              rejected = true
            end
            raise "invalid derived settings accepted" unless rejected
          end
          b = a.with(url: "http://127.0.0.1:#{servers.last.addr[1]}", api_key: "key-b")
          b = b.with(user_agent: "derived-agent")
          raise "derived wrapper lost type" unless b.is_a?(Microsandbox::RemoteContext)
          first = collection.get("task")
          second = Microsandbox::Sandbox.ctx(b).get("task")
          raise "destinations collapsed" if first.id == second.id
          a = b = nil
          GC.start
          raise "resource lost context" unless first.context.sandboxes.get("task").id == first.id
          raise "collection lost context" unless collection.get("task").id == first.id
          listed = collection.list["sandboxes"].first
          raise "listed resource lost identity" unless listed.id == first.id
          raise "listed resource lost context" unless listed.info["id"] == first.id
          raise "status must be a symbol in both views" unless first.status == :running && first.info["status"] == :running
          first.wait_for_status(:running)
          raise "wait must return nil" unless first.wait_for_status("running").nil?
          puts "native Ruby context checks passed"
        ensure
          workers.each(&:kill)
          servers.each(&:close)
        end
      CODE
      env = ENV.to_h.reject { |key, _| key.start_with?("MSB_") }
      env["MSB_HOME"] = File.join(directory, "home")
      output, status = Open3.capture2e(env, RbConfig.ruby, "-I", directory, "-e", script, unsetenv_others: true)
      abort output unless status.success?
      puts output
    end
  end
end
