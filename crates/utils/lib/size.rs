//! Byte-size types and conversion helpers.
//!
//! Provides [`ByteSize`], [`Bytes`], and [`Mebibytes`] for type-safe size
//! specification across the project. The [`SizeExt`] trait adds `.bytes()`,
//! `.kib()`, `.mib()`, and `.gib()` helpers to integer literals.
//!
//! ```ignore
//! use microsandbox_utils::size::{SizeExt, Mebibytes};
//!
//! // All equivalent — 512 MiB:
//! let a: Mebibytes = 512.into();    // bare integer
//! let b: Mebibytes = 512.mib().into(); // explicit unit
//!
//! // Cross-unit conversion:
//! let c: Mebibytes = 1.gib().into();  // 1 GiB → 1024 MiB
//! ```

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A byte-size value returned by [`SizeExt`] helpers.
///
/// Acts as the universal intermediate type that converts [`Into`] both
/// [`Bytes`] and [`Mebibytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

/// A size measured in bytes.
///
/// Accepted by APIs that operate at byte-level precision (e.g. filesystem
/// capacity, rlimit values).
///
/// **Bare integer path:** `u64` converts directly via [`From`].
/// **Helper path:** any [`ByteSize`] (from `.kib()`, `.mib()`, `.gib()`)
/// converts via [`From`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(u64);

/// A size measured in mebibytes (MiB).
///
/// Accepted by APIs that operate at MiB-level precision (e.g. sandbox
/// memory, volume quota, tmpfs size).
///
/// **Bare integer path:** `u32` converts directly via [`From`].
/// **Helper path:** any [`ByteSize`] (from `.kib()`, `.mib()`, `.gib()`)
/// converts via [`From`] (truncates to whole MiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mebibytes(u32);

/// Helper trait for readable byte sizes.
///
/// Implemented for common integer types so that literals like `512.mib()`
/// or `1.gib()` return a [`ByteSize`] that converts into either [`Bytes`]
/// or [`Mebibytes`].
pub trait SizeExt {
    /// Create a [`ByteSize`] representing this many bytes.
    fn bytes(self) -> ByteSize;
    /// Create a [`ByteSize`] representing this many kibibytes (×1024).
    fn kib(self) -> ByteSize;
    /// Create a [`ByteSize`] representing this many mebibytes (×1024²).
    fn mib(self) -> ByteSize;
    /// Create a [`ByteSize`] representing this many gibibytes (×1024³).
    fn gib(self) -> ByteSize;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ByteSize {
    /// Get the raw byte count.
    pub fn as_bytes(self) -> u64 {
        self.0
    }

    /// Get the value in whole mebibytes (truncates sub-MiB remainder).
    pub fn as_mib(self) -> u32 {
        (self.0 / (1024 * 1024)) as u32
    }
}

impl Bytes {
    /// Get the raw byte count.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl Mebibytes {
    /// Get the MiB count.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

// ByteSize → destination types.

impl From<ByteSize> for Bytes {
    fn from(bs: ByteSize) -> Self {
        Self(bs.0)
    }
}

impl From<ByteSize> for Mebibytes {
    fn from(bs: ByteSize) -> Self {
        Self((bs.0 / (1024 * 1024)) as u32)
    }
}

// Bare integers → destination types.

impl From<u64> for Bytes {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<u32> for Mebibytes {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

// SizeExt implementations for common integer types.

macro_rules! impl_size_ext {
    ($($t:ty),*) => {
        $(
            impl SizeExt for $t {
                fn bytes(self) -> ByteSize { ByteSize(self as u64) }
                fn kib(self) -> ByteSize { ByteSize(self as u64 * 1024) }
                fn mib(self) -> ByteSize { ByteSize(self as u64 * 1024 * 1024) }
                fn gib(self) -> ByteSize { ByteSize(self as u64 * 1024 * 1024 * 1024) }
            }
        )*
    };
}

impl_size_ext!(u8, u16, u32, u64, usize, i32);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_ext_helpers() {
        assert_eq!(1u64.kib().as_bytes(), 1024);
        assert_eq!(1u64.mib().as_bytes(), 1024 * 1024);
        assert_eq!(1u64.gib().as_bytes(), 1024 * 1024 * 1024);
        assert_eq!(512u64.mib().as_bytes(), 512 * 1024 * 1024);
        assert_eq!(64i32.mib().as_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn test_bytesize_to_mebibytes() {
        let mib: Mebibytes = 512.mib().into();
        assert_eq!(mib.as_u32(), 512);

        let mib: Mebibytes = 1.gib().into();
        assert_eq!(mib.as_u32(), 1024);
    }

    #[test]
    fn test_bytesize_to_bytes() {
        let b: Bytes = 64.mib().into();
        assert_eq!(b.as_u64(), 64 * 1024 * 1024);
    }

    #[test]
    fn test_bare_u32_to_mebibytes() {
        let mib: Mebibytes = 512u32.into();
        assert_eq!(mib.as_u32(), 512);
    }

    #[test]
    fn test_bare_u64_to_bytes() {
        let b: Bytes = 4096u64.into();
        assert_eq!(b.as_u64(), 4096);
    }

    #[test]
    fn test_truncation() {
        // 1.5 MiB → truncates to 1 MiB
        let bs = ByteSize(1024 * 1024 + 512 * 1024);
        let mib: Mebibytes = bs.into();
        assert_eq!(mib.as_u32(), 1);
    }

    #[test]
    fn test_bytes_helper() {
        assert_eq!(4096.bytes().as_bytes(), 4096);
    }
}
