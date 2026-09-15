"""Exception hierarchy for microsandbox errors.

All classes accept a single string message (for FFI from Rust) or their
documented keyword arguments (for direct Python construction).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


class MicrosandboxError(Exception):
    """Base exception for all microsandbox errors."""
    code: str = "microsandbox-error"


class RuntimeNotInstalledError(MicrosandboxError):
    """No complete host runtime pair could be found."""
    code = "runtime-not-installed"


class RuntimeIncompleteError(MicrosandboxError):
    """The selected host runtime is partial or an explicit binary path is invalid."""
    code = "runtime-incomplete"


class InvalidConfigError(MicrosandboxError):
    """Invalid sandbox configuration."""
    code = "invalid-config"


class NoDefaultCommandError(MicrosandboxError):
    """Sandbox configuration does not provide an executable default command."""
    code = "no-default-command"


class CloudHttpError(MicrosandboxError):
    """Cloud control-plane request failed."""
    code = "cloud-http"


class SandboxNotFoundError(MicrosandboxError):
    """Sandbox does not exist."""
    code = "sandbox-not-found"


class SandboxNotRunningError(MicrosandboxError):
    """Sandbox exists but is not running."""
    code = "sandbox-not-running"


class SandboxAlreadyExistsError(MicrosandboxError):
    """A sandbox with this name already exists."""
    code = "sandbox-already-exists"


class SandboxReplacedError(MicrosandboxError):
    """A handle's name now refers to a different persisted sandbox."""
    code = "sandbox-replaced"


class SandboxStillRunningError(MicrosandboxError):
    """Cannot perform operation because sandbox is still running."""
    code = "sandbox-still-running"


class ExecTimeoutError(MicrosandboxError):
    """Command execution timed out."""
    code = "exec-timeout"


class StopTimeoutError(MicrosandboxError, TimeoutError):
    """Graceful shutdown did not complete within its budget; no kill was requested."""
    code = "stop-timeout"


class ExecFailedError(MicrosandboxError):
    """Command execution failed."""
    code = "exec-failed"


class FilesystemError(MicrosandboxError):
    """Filesystem operation failed."""
    code = "filesystem-error"


class PathNotFoundError(MicrosandboxError):
    """Path does not exist in the sandbox."""
    code = "path-not-found"


class VolumeNotFoundError(MicrosandboxError):
    """Volume does not exist."""
    code = "volume-not-found"


class ImageNotFoundError(MicrosandboxError):
    """Image reference could not be resolved."""
    code = "image-not-found"


class ImageInUseError(MicrosandboxError):
    """Image is still referenced by one or more sandboxes."""
    code = "image-in-use"


class ImagePullFailedError(MicrosandboxError):
    """Image pull failed."""
    code = "image-pull-failed"


class NetworkPolicyError(MicrosandboxError):
    """Network policy violation or configuration error."""
    code = "network-policy-error"


class SecretViolationError(MicrosandboxError):
    """Secret was sent to a disallowed host."""
    code = "secret-violation"


class TlsError(MicrosandboxError):
    """TLS interception error."""
    code = "tls-error"


class IoError(MicrosandboxError):
    """I/O error."""
    code = "io-error"


class MetricsDisabledError(MicrosandboxError):
    """Metrics sampling is disabled for this sandbox."""
    code = "metrics-disabled"


class MetricsUnavailableError(MicrosandboxError):
    """Metrics are not available for the sandbox's current run."""
    code = "metrics-unavailable"


class UnsupportedOperationError(MicrosandboxError):
    """The sandbox runtime is too old for the requested operation."""
    code = "unsupported-operation"


class UnsupportedError(MicrosandboxError):
    """The selected backend does not support a requested feature yet."""
    code = "unsupported"


class SnapshotMigrationError(MicrosandboxError):
    """A snapshot could not complete its adjacent-release migration."""
    code = "snapshot-migration"


@dataclass(frozen=True)
class PublishedSnapshotArtifact:
    """A completed snapshot retained after source recovery failed."""

    kind: Literal["installed", "archive"]
    path: str
    snapshot_id: str
    digest: str


class SnapshotSourceRecoveryError(MicrosandboxError):
    """Capture completed, but the source requires recovery before further use.

    ``artifact`` is set only when the requested snapshot was published. Otherwise,
    ``checkpoint_path`` identifies the retained runtime-local checkpoint; removing
    the source may remove it. This error does not imply that ordinary resume is safe.
    """

    code = "snapshot-source-recovery"

    def __init__(
        self,
        message: str,
        *,
        source_sandbox: str,
        checkpoint_id: str,
        checkpoint_root: str,
        checkpoint_path: str,
        artifact: dict | None,
        detail: str,
        publication_error: str | None,
    ) -> None:
        super().__init__(message)
        self.source_sandbox = source_sandbox
        self.checkpoint_id = checkpoint_id
        self.checkpoint_root = checkpoint_root
        self.checkpoint_path = checkpoint_path
        self.artifact = PublishedSnapshotArtifact(**artifact) if artifact is not None else None
        self.detail = detail
        self.publication_error = publication_error
