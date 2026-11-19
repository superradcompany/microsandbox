# Opt-in live selector reads; report no credentials or resource metadata.
require "microsandbox"
require "json"
abort "Set MSB_REMOTE_SELECTOR_LIVE=1 to opt in" unless ENV["MSB_REMOTE_SELECTOR_LIVE"] == "1"
results = [Microsandbox::Sandbox, Microsandbox::Volume, Microsandbox::Snapshot].map do |resource|
  feature = "#{resource.name.split('::').last.downcase}_list"
  begin
    resource.remote.list
    result = {feature: feature, verdict: "PASS"}
  rescue StandardError => error
    result = {feature: feature, verdict: "FAIL", errorType: error.class.name, status: error.message[/\b(4\d\d|5\d\d)\b/]}
  end
  puts JSON.generate(result)
  result
end
File.write(ENV["MSB_SELECTOR_REPORT"], JSON.pretty_generate(results) + "\n") if ENV["MSB_SELECTOR_REPORT"]
exit(results.any? { |result| result[:verdict] == "FAIL" } ? 1 : 0)
