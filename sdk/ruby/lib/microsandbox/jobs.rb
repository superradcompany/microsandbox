# frozen_string_literal: true

require "json"

module Microsandbox
  class JobError < Error
    attr_reader :code, :job_id

    def initialize(payload)
      details = JSON.parse(payload)
      @code = details.fetch("code")
      @job_id = details["job_id"]
      super(details.fetch("message"))
    end
  end

  JobInfo = Data.define(:id, :runtime_boot_id, :command, :state, :tty, :stdin_closed,
                       :pid, :created_at, :started_at, :finished_at, :exit_code,
                       :failure, :error, :timed_out) do
    def self.from_hash(value)
      new(**value.transform_keys(&:to_sym).slice(*members))
    end
  end
  JobPage = Data.define(:items, :next_cursor)
  JobExit = Data.define(:code, :success, :timed_out)
  JobLogEntry = Data.define(:timestamp, :source, :data, :cursor) do
    def self.from_hash(value)
      new(timestamp: value.fetch("timestamp"), source: value.fetch("source"),
          data: value.fetch("data_base64").unpack1("m0"), cursor: value.fetch("cursor"))
    end
  end
  JobEvent = Data.define(:type, :value)

  module JobListing
    def list_jobs(all: false, limit: 50, cursor: nil)
      page = JSON.parse(_jobs_json(all: all, limit: limit, cursor: cursor))
      JobPage.new(items: page.fetch("items").map { |item| JobInfo.from_hash(item) }, next_cursor: page["next_cursor"])
    end
  end
  Sandbox.include(JobListing)
  SandboxHandle.include(JobListing)

  class Job
    def inspect = JobInfo.from_hash(JSON.parse(_inspect_json))
    def wait = JobExit.new(**JSON.parse(_wait_json).transform_keys(&:to_sym))

    def logs(tail: nil, since: nil, until: nil, sources: [], from_cursor: nil)
      options = { tail: tail, since: since, until: binding.local_variable_get(:until), sources: sources, from_cursor: from_cursor }.compact
      JSON.parse(_logs_json(JSON.generate(options))).map { |item| JobLogEntry.from_hash(item) }
    end

    def log_stream(tail: nil, since: nil, until: nil, sources: [], from_cursor: nil, follow: false)
      options = { tail: tail, since: since, until: binding.local_variable_get(:until), sources: sources, from_cursor: from_cursor, follow: follow }.compact
      _log_stream(JSON.generate(options))
    end

    def follow_logs(**options) = log_stream(**options, follow: true)
  end

  class JobAttachment
    include Enumerable
    def recv
      raw = _recv_json
      return nil unless raw
      event = JSON.parse(raw)
      value = case event.fetch("type")
              when "output" then JobLogEntry.from_hash(event.fetch("value"))
              when "completed" then JobInfo.from_hash(event.fetch("value"))
              else event.fetch("value")
              end
      JobEvent.new(type: event.fetch("type"), value: value)
    end

    def each
      return enum_for(:each) unless block_given?
      begin
        while (event = recv)
          yield event
        end
      ensure
        detach
      end
    end
    alias close detach
  end

  class JobLogStream
    include Enumerable
    def next
      raw = _next_json
      raw ? JobLogEntry.from_hash(JSON.parse(raw)) : nil
    end

    def each
      return enum_for(:each) unless block_given?
      begin
        while (entry = self.next)
          yield entry
        end
      ensure
        close
      end
    end
  end
end
