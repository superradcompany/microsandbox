# frozen_string_literal: true

module Microsandbox
  class Sandbox
    def self.with(name, **options)
      sandbox = create(name, **options)
      return sandbox unless block_given?

      begin
        yield sandbox
      ensure
        # Ruby automatically retains a body exception as the cleanup error's
        # cause. The native owner targets its captured run and ignores nonowners.
        sandbox.__send__(:__shutdown_owned)
      end
    end

    private :__shutdown_owned

  end
end
