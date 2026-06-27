//! Removal and rename operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn remove_inode_path(&self, path: &Path) {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.remove(path) {
            inodes.by_inode.remove(&data.inode);
        }
    }

    pub(super) fn rename_inode_path(&self, old_path: &Path, new_path: &Path) {
        let mut inodes = self.inodes.write().unwrap();
        let Some(old_data) = inodes.by_path.remove(old_path) else {
            if let Some(replaced) = inodes.by_path.remove(new_path) {
                inodes.by_inode.remove(&replaced.inode);
            }
            return;
        };

        if let Some(replaced) = inodes.by_path.remove(new_path) {
            inodes.by_inode.remove(&replaced.inode);
        }

        // Keep the guest-visible source inode alive across atomic replacement,
        // e.g. heartbeat.tmp -> heartbeat.json.
        let data = Arc::new(InodeData {
            inode: old_data.inode,
            path: new_path.to_path_buf(),
            virtual_meta: RwLock::new(old_data.virtual_meta.read().unwrap().clone()),
        });
        inodes.by_inode.insert(data.inode, data.clone());
        inodes.by_path.insert(new_path.to_path_buf(), data);
    }
}
