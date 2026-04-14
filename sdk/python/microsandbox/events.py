"""Sealed discriminated union types for execution and pull progress events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

#--------------------------------------------------------------------------------------------------
# Types: Exec Events
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class StartedEvent:
    """Process started."""
    pid: int

@dataclass(frozen=True, slots=True)
class StdoutEvent:
    """Stdout data."""
    data: bytes

@dataclass(frozen=True, slots=True)
class StderrEvent:
    """Stderr data."""
    data: bytes

@dataclass(frozen=True, slots=True)
class ExitedEvent:
    """Process exited."""
    code: int

ExecEvent: TypeAlias = StartedEvent | StdoutEvent | StderrEvent | ExitedEvent

#--------------------------------------------------------------------------------------------------
# Types: Pull Progress Events
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Resolving:
    """Resolving the image reference."""
    reference: str

@dataclass(frozen=True, slots=True)
class Resolved:
    """Manifest parsed."""
    reference: str
    manifest_digest: str
    layer_count: int
    total_download_bytes: int | None

@dataclass(frozen=True, slots=True)
class LayerDownloadProgress:
    """Byte-level download progress for a single layer."""
    layer_index: int
    digest: str
    downloaded_bytes: int
    total_bytes: int | None

@dataclass(frozen=True, slots=True)
class LayerDownloadComplete:
    """A single layer download completed."""
    layer_index: int
    digest: str
    downloaded_bytes: int

@dataclass(frozen=True, slots=True)
class LayerExtractStarted:
    """Layer extraction started."""
    layer_index: int
    diff_id: str

@dataclass(frozen=True, slots=True)
class LayerExtractProgress:
    """Byte-level extraction progress for a single layer."""
    layer_index: int
    bytes_read: int
    total_bytes: int

@dataclass(frozen=True, slots=True)
class LayerExtractComplete:
    """Layer extraction completed."""
    layer_index: int
    diff_id: str

@dataclass(frozen=True, slots=True)
class LayerIndexStarted:
    """Sidecar index generation started."""
    layer_index: int

@dataclass(frozen=True, slots=True)
class LayerIndexComplete:
    """Sidecar index generation completed."""
    layer_index: int

@dataclass(frozen=True, slots=True)
class PullComplete:
    """Entire image pull completed."""
    reference: str
    layer_count: int

PullProgress: TypeAlias = (
    Resolving | Resolved
    | LayerDownloadProgress | LayerDownloadComplete
    | LayerExtractStarted | LayerExtractProgress | LayerExtractComplete
    | LayerIndexStarted | LayerIndexComplete
    | PullComplete
)
