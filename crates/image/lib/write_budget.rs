//! Opt-in aggregate admission for every cache write made by one image operation.

use std::cell::RefCell;
use std::fs::File;
use std::future::Future;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BLOCK_BYTES: u64 = 4096;
const FILE_HEADROOM: u64 = 32 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A shared, nonrefundable write allowance. Clones keep the embedding worker's
/// durable owner alive until detached layer tasks and blocking writers finish.
#[derive(Clone)]
pub struct ImageWriteBudget {
    remaining: Arc<AtomicU64>,
    _owner: Arc<dyn Send + Sync>,
}

pub(crate) struct BudgetedFile {
    file: File,
    budget: Option<ImageWriteBudget>,
    position: u64,
    charged_end: u64,
}

pub(crate) struct ScopeGuard(Option<ImageWriteBudget>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImageWriteBudget {
    /// Create a byte allowance backed by the caller's durable capacity owner.
    /// New cache objects created inside `scope` inherit this shared allowance.
    /// The owner must retain the reservation while any clone can still write.
    pub fn new(maximum_bytes: u64, owner: Arc<dyn Send + Sync>) -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(maximum_bytes)),
            _owner: owner,
        }
    }

    /// Bound image-cache writes without changing ordinary SDK calls or formats.
    /// Downloads, spools, EROFS, flat ext4 and metadata share one allowance.
    /// This scope must cover cache construction and the complete image operation.
    pub async fn scope<F: Future>(&self, operation: F) -> F::Output {
        ACTIVE.scope(self.clone(), operation).await
    }

    pub(crate) fn current() -> Option<Self> {
        ACTIVE
            .try_with(Clone::clone)
            .ok()
            .or_else(|| BLOCKING.with(|current| current.borrow().clone()))
    }

    pub(crate) async fn scope_optional<F: Future>(budget: Option<Self>, operation: F) -> F::Output {
        match budget {
            Some(budget) => budget.scope(operation).await,
            None => operation.await,
        }
    }

    pub(crate) fn enter(budget: Option<Self>) -> ScopeGuard {
        ScopeGuard(BLOCKING.with(|current| current.replace(budget)))
    }

    pub(crate) fn charge(&self, bytes: u64) -> io::Result<()> {
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::StorageFull,
                    "image operation exceeds its admitted byte allowance",
                )
            })
    }

    pub(crate) fn charge_file(&self) -> io::Result<()> {
        self.charge(FILE_HEADROOM)
    }

    pub(crate) fn charge_growth(&self, old: u64, new: u64) -> io::Result<()> {
        let rounded = |bytes: u64| {
            bytes
                .checked_add(BLOCK_BYTES - 1)
                .map(|bytes| bytes / BLOCK_BYTES * BLOCK_BYTES)
        };
        let old = rounded(old).ok_or_else(|| io::Error::other("image byte bound overflow"))?;
        let new = rounded(new).ok_or_else(|| io::Error::other("image byte bound overflow"))?;
        self.charge(new.saturating_sub(old))
    }
}

impl BudgetedFile {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        Self::create_with_budget(path, ImageWriteBudget::current())
    }

    pub(crate) fn create_with_budget(
        path: &Path,
        budget: Option<ImageWriteBudget>,
    ) -> io::Result<Self> {
        if let Some(budget) = &budget {
            budget.charge_file()?;
        }
        Ok(Self {
            file: File::create(path)?,
            budget,
            position: 0,
            charged_end: 0,
        })
    }

    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Write for BudgetedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("image file offset overflow"))?;
        if let Some(budget) = &self.budget {
            budget.charge_growth(self.charged_end, end)?;
        }
        self.charged_end = self.charged_end.max(end);
        let written = self.file.write(bytes)?;
        self.position += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for BudgetedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = self.file.seek(position)?;
        Ok(self.position)
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        BLOCKING.with(|current| current.replace(self.0.take()));
    }
}

thread_local! { static BLOCKING: RefCell<Option<ImageWriteBudget>> = const { RefCell::new(None) }; }
tokio::task_local! { static ACTIVE: ImageWriteBudget; }

#[cfg(test)]
mod tests {
    use super::*;

    use crate::erofs::{self, fsmeta};
    use crate::ext4::{Ext4RootfsOptions, materialize_ext4_rootfs};
    use crate::tree::{DataSpool, FileTree};

    #[tokio::test]
    async fn materializers_share_one_allowance_and_refuse_before_growth() {
        let directory = tempfile::tempdir().unwrap();
        let budget = ImageWriteBudget::new(FILE_HEADROOM + BLOCK_BYTES, Arc::new(()));
        budget
            .scope(async {
                let mut spool = DataSpool::new(&directory.path().join("spool")).unwrap();
                spool.write_chunk(&[1; BLOCK_BYTES as usize]).unwrap();
                assert!(spool.write_chunk(&[2]).is_err());
                assert_eq!(
                    std::fs::metadata(directory.path().join("spool"))
                        .unwrap()
                        .len(),
                    BLOCK_BYTES
                );
                let erofs = directory.path().join("layer.erofs");
                assert!(erofs::write_erofs(&FileTree::new(), &erofs).is_err());
                assert!(
                    !erofs.exists(),
                    "a second writer cannot reuse the spool's allowance"
                );
            })
            .await;

        for output in ["layer.erofs", "fsmeta.erofs", "rootfs.vmdk", "flat.ext4"] {
            let path = directory.path().join(output);
            let budget = ImageWriteBudget::new(0, Arc::new(()));
            budget
                .scope(async {
                    let tree = FileTree::new();
                    let failed = match output {
                        "layer.erofs" => erofs::write_erofs(&tree, &path).is_err(),
                        "fsmeta.erofs" => {
                            fsmeta::write_fsmeta(&tree, &Default::default(), &[], &path).is_err()
                        }
                        "rootfs.vmdk" => crate::write_vmdk_descriptor(&path, &[]).is_err(),
                        _ => materialize_ext4_rootfs(&path, tree, &Ext4RootfsOptions::default())
                            .is_err(),
                    };
                    assert!(failed, "{output} ignored byte admission");
                    assert!(!path.exists(), "{output} wrote before byte admission");
                })
                .await;
        }
        let path = directory.path().join("ordinary.erofs");
        erofs::write_erofs(&FileTree::new(), &path).unwrap();
        assert!(
            path.exists(),
            "ordinary callers retain their existing behavior"
        );
    }

    #[tokio::test]
    async fn detached_writers_retain_the_capacity_owner() {
        let (release, released) = tokio::sync::oneshot::channel();
        let owner = Arc::new(());
        let observer = Arc::downgrade(&owner);
        let budget = ImageWriteBudget::new(FILE_HEADROOM + BLOCK_BYTES, owner);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("detached");
        let inherited = budget.scope(async { ImageWriteBudget::current() }).await;
        let writer = tokio::spawn(ImageWriteBudget::scope_optional(inherited, async move {
            released.await.unwrap();
            let budget = ImageWriteBudget::current();
            tokio::task::spawn_blocking(move || {
                let _scope = ImageWriteBudget::enter(budget);
                let mut file = BudgetedFile::create(&path).unwrap();
                file.write_all(&[7; BLOCK_BYTES as usize]).unwrap();
                assert!(file.write_all(&[8]).is_err());
            })
            .await
            .unwrap();
        }));
        drop(budget);
        assert!(
            observer.upgrade().is_some(),
            "cancelled caller released a live writer's owner"
        );
        release.send(()).unwrap();
        writer.await.unwrap();
        assert!(observer.upgrade().is_none());
        assert_eq!(
            std::fs::metadata(directory.path().join("detached"))
                .unwrap()
                .len(),
            BLOCK_BYTES
        );
    }
}
