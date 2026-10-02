# frozen_string_literal: true

module Microsandbox
  # Base class for every error reported by a sandbox, image, volume, snapshot,
  # or backend operation. Defined natively by the extension; reopened here to
  # attach the stable, machine-readable code. Argument validation is outside
  # this hierarchy: it keeps raising +ArgumentError+ / +TypeError+.
  #
  # The native layer raises the subclass matching the core error variant;
  # variants without a dedicated class surface as +Error+ itself, so
  # +rescue Microsandbox::Error+ keeps catching all of them. Class names and
  # codes mirror the Python SDK (sdk/python/microsandbox/errors.py); the
  # Snapshot*, ExecFailed, and VolumeAlreadyExists classes follow the Go SDK's
  # finer per-variant coverage.
  class Error
    CODE = "microsandbox-error"

    # The stable, machine-readable error code for this class.
    def self.code
      const_get(:CODE)
    end

    # The stable, machine-readable error code for this instance.
    def code
      self.class.code
    end
  end

  # Defines +Microsandbox::<name>+ as a direct subclass of +Error+ carrying +code+.
  def self.define_error(name, code)
    klass = Class.new(Error)
    klass.const_set(:CODE, code)
    const_set(name, klass)
  end
  private_class_method :define_error

  # Runtime bootstrap errors ------------------------------------------------
  # Neither member of the host runtime pair (msb + libkrunfw) is installed;
  # Microsandbox.install fetches it.
  define_error(:RuntimeNotInstalledError, "runtime-not-installed")
  # Only one member of the host runtime pair is available.
  define_error(:RuntimeIncompleteError, "runtime-incomplete")

  # Configuration / validation errors --------------------------------------
  define_error(:InvalidConfigError, "invalid-config")
  # exec_default/attach_default on an image whose ENTRYPOINT+CMD provide no
  # executable command.
  define_error(:NoDefaultCommandError, "no-default-command")

  # Lifecycle errors --------------------------------------------------------
  define_error(:SandboxNotFoundError, "sandbox-not-found")
  define_error(:SandboxNotRunningError, "sandbox-not-running")
  define_error(:SandboxAlreadyExistsError, "sandbox-already-exists")
  # A handle was bound to an older sandbox that has since been replaced by
  # another sandbox with the same name; the stale lifecycle call is refused.
  define_error(:SandboxReplacedError, "sandbox-replaced")
  define_error(:SandboxStillRunningError, "sandbox-still-running")
  # Reserved for parity with the Python SDK; no core code path raises this
  # variant today.
  define_error(:SandboxStopTimedOutError, "sandbox-stop-timed-out")
  # A graceful stop with an explicit timeout did not complete in time. The
  # shutdown request may still complete; no kill was requested.
  define_error(:StopTimeoutError, "stop-timeout")

  # Execution errors --------------------------------------------------------
  define_error(:ExecTimeoutError, "exec-timeout")
  # The command failed to spawn (binary not found, permission denied, ...), as
  # opposed to exiting non-zero.
  define_error(:ExecFailedError, "exec-failed")

  # Filesystem errors -------------------------------------------------------
  define_error(:FilesystemError, "filesystem-error")
  # Reserved for parity with the Python SDK; no core variant maps here today
  # (a missing guest path raises FilesystemError).
  define_error(:PathNotFoundError, "path-not-found")

  # Volume / image errors ---------------------------------------------------
  define_error(:VolumeNotFoundError, "volume-not-found")
  define_error(:VolumeAlreadyExistsError, "volume-already-exists")
  define_error(:ImageNotFoundError, "image-not-found")
  define_error(:ImageInUseError, "image-in-use")
  # Reserved for parity with the Python SDK; no core variant maps here today.
  define_error(:ImagePullFailedError, "image-pull-failed")

  # Snapshot errors ---------------------------------------------------------
  define_error(:SnapshotNotFoundError, "snapshot-not-found")
  define_error(:SnapshotAlreadyExistsError, "snapshot-already-exists")
  define_error(:SnapshotSandboxRunningError, "snapshot-sandbox-running")
  define_error(:SnapshotImageMissingError, "snapshot-image-missing")
  define_error(:SnapshotIntegrityError, "snapshot-integrity")
  # Capture completed, but the source sandbox failed to recover its prior
  # execution state; see the class body below for the recovery locator.
  define_error(:SnapshotSourceRecoveryError, "snapshot-source-recovery")
  # The automatic adjacent-release snapshot migration was blocked.
  define_error(:SnapshotMigrationError, "snapshot-migration")

  # Networking / secrets errors ---------------------------------------------
  # Also carries the core's network policy build/validation error.
  define_error(:NetworkPolicyError, "network-policy-error")
  # Reserved for parity with the Python SDK; no core variant maps here today.
  define_error(:SecretViolationError, "secret-violation")
  # Reserved for parity with the Python SDK; no core variant maps here today.
  define_error(:TlsError, "tls-error")

  # I/O ---------------------------------------------------------------------
  define_error(:IoError, "io-error")

  # Metrics errors ----------------------------------------------------------
  define_error(:MetricsDisabledError, "metrics-disabled")
  define_error(:MetricsUnavailableError, "metrics-unavailable")

  # Runtime compatibility ---------------------------------------------------
  # The sandbox runtime is too old for the requested operation.
  define_error(:UnsupportedOperationError, "unsupported-operation")

  # Cloud / backend routing errors ------------------------------------------
  define_error(:CloudHttpError, "cloud-http")
  # The selected backend does not support the requested feature yet. Distinct
  # from UnsupportedOperationError above.
  define_error(:UnsupportedError, "unsupported")

  # The native layer renders the rejected operation and the remedy into the
  # message ("sandbox.kill is not supported by this backend: use ...") and
  # also attaches them as structured attributes, mirroring the Python SDK's
  # +UnsupportedError.operation+ / +.hint+.
  class UnsupportedError
    # @return [String, nil] the rejected API in Ruby rendering, e.g. "sandbox.kill"
    attr_reader :operation
    # @return [String, nil] why it was rejected or what to use instead
    attr_reader :hint
  end

  # The native layer attaches the recovery locator as attributes, mirroring
  # the Python SDK's +SnapshotSourceRecoveryError+. +artifact+ is set only when
  # the requested snapshot was published; otherwise +checkpoint_path+ names the
  # retained runtime-local checkpoint, which removing the source may remove.
  # This error does not imply that the source is running or safe to resume.
  class SnapshotSourceRecoveryError
    # @return [String, nil] the sandbox whose post-capture recovery failed
    attr_reader :source_sandbox
    # @return [String, nil] the verified runtime checkpoint identity
    attr_reader :checkpoint_id
    # @return [String, nil] the content-addressed root of that checkpoint
    attr_reader :checkpoint_root
    # @return [String, nil] the runtime-local checkpoint path
    attr_reader :checkpoint_path
    # @return [Hash, nil] the published snapshot, with "kind" ("installed" or
    #   "archive"), "path", "snapshot_id", and "digest" keys
    attr_reader :artifact
    # @return [String, nil] the runtime's recovery diagnostic
    attr_reader :detail
    # @return [String, nil] a further failure publishing the requested artifact
    attr_reader :publication_error
  end
end
