# Repeat fresh Ruby connections to the exact shared fixture. No resource mutation
# beyond the implicit start required by shell; setup and cleanup remain external.
require 'json'
require 'microsandbox'

abort 'explicit remote audit opt-in required' unless ENV['MSB_REMOTE_AUDIT'] == '1'
fixture = JSON.parse(File.read(ENV.fetch('MSB_INSPECTION_FIXTURE')))
concurrency = Integer(ENV.fetch('MSB_CONNECTION_CONCURRENCY', '1'))
attempts = Integer(ENV.fetch('MSB_CONNECTION_ATTEMPTS', '12'))
abort 'use 1–4 threads and 1–48 attempts' unless (1..4).cover?(concurrency) && (1..48).cover?(attempts)

# Prewarm once so concurrent connections cannot compete to start a stopped VM.
sandbox = Microsandbox::Sandbox.remote.get(fixture.fetch('name'))
raise 'identity mismatch' unless sandbox.id == fixture.fetch('id')
sandbox.ensure_running

work = Queue.new
attempts.times { |i| work << i }
rows = []
lock = Mutex.new
threads = concurrency.times.map do
  Thread.new do
    loop do
      begin
        attempt = work.pop(true)
      rescue ThreadError
        break
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      begin
        receiver = Microsandbox::Sandbox.remote.get(fixture.fetch('name'))
        raise 'identity mismatch' unless receiver.id == fixture.fetch('id')
        raise 'unexpected output' unless receiver.shell('printf ready').stdout == 'ready'
        row = { attempt: attempt, verdict: 'PASS' }
      rescue StandardError => error
        row = { attempt: attempt, verdict: 'FAIL', reason: error.message.gsub(ENV.fetch('MSB_API_KEY'), '[redacted]') }
      end
      row[:elapsed_ms] = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
      lock.synchronize do
        rows << row
        File.write(ENV.fetch('MSB_AUDIT_REPORT'), JSON.pretty_generate(concurrency: concurrency, rows: rows.sort_by { |r| r[:attempt] }) + "\n")
      end
    end
  end
end
threads.each(&:value)
exit(rows.any? { |r| r[:verdict] == 'FAIL' } ? 1 : 0)
