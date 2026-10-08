# frozen_string_literal: true

require "test/unit"
require "timeout"
require_relative "../lib/microsandbox"

class ManagedJobsTest < Test::Unit::TestCase
  def test_job_errors_preserve_uncertain_launch_identity
    error = Microsandbox::JobError.new(JSON.generate(code: "launch_unconfirmed", message: "connection lost", job_id: "job_123"))
    assert_kind_of Microsandbox::Error, error
    assert_equal "launch_unconfirmed", error.code
    assert_equal "connection lost", error.message
    assert_equal "job_123", error.job_id
  end

  def test_job_logs_preserve_binary_bytes
    bytes = "\xFF\x00\n".b
    entry = Microsandbox::JobLogEntry.from_hash("timestamp" => 42, "source" => "stdout", "data_base64" => [bytes].pack("m0"), "cursor" => "job:1")
    assert_equal bytes, entry.data
    assert_equal Encoding::BINARY, entry.data.encoding
  end

  def test_live_detach_reattach_and_eof
    omit("set MSB_HOME and MSB_JOB_TEST_SANDBOX to a disposable running VM") unless ENV["MSB_HOME"] && ENV["MSB_JOB_TEST_SANDBOX"]
    job = nil
    attachments = []
    Timeout.timeout(20) do
      sandbox = Microsandbox::Sandbox.get(ENV.fetch("MSB_JOB_TEST_SANDBOX")).connect
      job = sandbox.exec_detached("cat")
      first = job.attach
      attachments << first
      error = assert_raise(Microsandbox::JobError) { job.attach }
      assert_equal "input_busy", error.code
      first.write_stdin("\xFF\x00\n".b)
      assert_equal "\xFF\x00\n".b, first.recv.value.data
      first.detach
      found = sandbox.get_job(job.id)
      second = found.attach
      attachments << second
      second.write_stdin("reattached\n")
      found.eof
      assert_true found.wait.success
      second.detach
      assert_equal "\xFF\x00\nreattached\n".b, found.logs.map(&:data).join
      cursor = nil
      loop do
        page = sandbox.list_jobs(all: true, cursor: cursor)
        break if page.items.any? { |item| item.id == job.id }
        assert_not_nil page.next_cursor, "job missing from retained history"
        cursor = page.next_cursor
      end
    end
  ensure
    attachments&.each { |attachment| attachment.detach rescue nil }
    job&.kill rescue nil
  end
end
