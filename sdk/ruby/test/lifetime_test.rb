# frozen_string_literal: true

require "test/unit"

# This pure Ruby suite exercises the actual block wrapper without a native VM.
module LifetimeFixture
  module Microsandbox
    class Sandbox
      attr_accessor :cleanup_error
      attr_reader :cleanups

      def self.create(*) = new

      def __shutdown_owned
        @cleanups = (@cleanups || 0) + 1
        raise cleanup_error if cleanup_error
      end
    end
  end
end

LifetimeFixture.module_eval(File.read(File.expand_path("../lib/microsandbox/lifetime.rb", __dir__)))

class LifetimeTest < Test::Unit::TestCase
  def test_returns_body_result_and_runs_cleanup
    sandbox = nil
    result = LifetimeFixture::Microsandbox::Sandbox.with("task") do |sb|
      sandbox = sb
      :result
    end
    assert_equal :result, result
    assert_equal 1, sandbox.cleanups
  end

  def test_no_block_returns_resource_without_cleanup
    sandbox = LifetimeFixture::Microsandbox::Sandbox.with("task")
    assert_nil sandbox.cleanups
  end

  def test_body_failure_is_not_suppressed
    failure = RuntimeError.new("body failed")
    sandbox = nil
    raised = assert_raise(RuntimeError) do
      LifetimeFixture::Microsandbox::Sandbox.with("task") do |sb|
        sandbox = sb
        raise failure
      end
    end
    assert_same failure, raised
    assert_equal 1, sandbox.cleanups
  end

  def test_cleanup_failure_is_not_suppressed
    cleanup = RuntimeError.new("cleanup failed")
    raised = assert_raise(RuntimeError) do
      LifetimeFixture::Microsandbox::Sandbox.with("task") { |sb| sb.cleanup_error = cleanup }
    end
    assert_same cleanup, raised
  end

  def test_cleanup_failure_preserves_body_failure_as_cause
    body = RuntimeError.new("body failed")
    cleanup = RuntimeError.new("cleanup failed")
    raised = assert_raise(RuntimeError) do
      LifetimeFixture::Microsandbox::Sandbox.with("task") do |sb|
        sb.cleanup_error = cleanup
        raise body
      end
    end
    assert_same cleanup, raised
    assert_same body, raised.cause
  end
end
