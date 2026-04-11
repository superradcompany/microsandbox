"""Exception hierarchy for microsandbox errors.

All classes accept a single string message (for FFI from Rust) or their
documented keyword arguments (for direct Python construction).
"""

from __future__ import annotations


class MicrosandboxError(Exception):
    """Base exception for all microsandbox errors."""
    code: str = "microsandbox-error"


class InvalidConfigError(MicrosandboxError):
    """Invalid sandbox configuration."""
    code = "invalid-config"


class SandboxNotFoundError(MicrosandboxError):
    """Sandbox does not exist."""
    code = "sandbox-not-found"


class SandboxNotRunningError(MicrosandboxError):
    """Sandbox exists but is not running."""
    code = "sandbox-not-running"


class SandboxAlreadyExistsError(MicrosandboxError):
    """A sandbox with this name already exists."""
    code = "sandbox-already-exists"


class SandboxStillRunningError(MicrosandboxError):
    """Cannot perform operation because sandbox is still running."""
    code = "sandbox-still-running"


class ExecTimeoutError(MicrosandboxError):
    """Command execution timed out."""
    code = "exec-timeout"


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
