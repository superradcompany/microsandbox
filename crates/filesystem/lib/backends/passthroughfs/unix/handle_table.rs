//! Open handles indexed by handle ID and inode, under the same table lock.

use std::{collections::BTreeMap, ops::Deref, sync::Arc};

use crate::backends::shared::handle_table::HandleData;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct FileHandles {
    by_handle: BTreeMap<u64, Arc<HandleData>>,
    by_inode: BTreeMap<(u64, u64), Arc<HandleData>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FileHandles {
    pub(super) fn for_inode(&self, inode: u64) -> Option<&Arc<HandleData>> {
        self.by_inode
            .range((inode, 0)..=(inode, u64::MAX))
            .next()
            .map(|(_, data)| data)
    }

    pub(super) fn insert(&mut self, handle: u64, data: Arc<HandleData>) {
        if let Some(previous) = self.by_handle.insert(handle, data.clone()) {
            self.by_inode.remove(&(previous.inode, handle));
        }
        self.by_inode.insert((data.inode, handle), data);
    }

    pub(super) fn remove(&mut self, handle: &u64) {
        if let Some(data) = self.by_handle.remove(handle) {
            self.by_inode.remove(&(data.inode, *handle));
        }
    }

    pub(super) fn clear(&mut self) {
        self.by_inode.clear();
        self.by_handle.clear();
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for FileHandles {
    type Target = BTreeMap<u64, Arc<HandleData>>;

    fn deref(&self) -> &Self::Target {
        &self.by_handle
    }
}

impl From<BTreeMap<u64, Arc<HandleData>>> for FileHandles {
    fn from(by_handle: BTreeMap<u64, Arc<HandleData>>) -> Self {
        let by_inode = by_handle
            .iter()
            .map(|(handle, data)| ((data.inode, *handle), data.clone()))
            .collect();
        Self {
            by_handle,
            by_inode,
        }
    }
}
