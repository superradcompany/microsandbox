use oci_spec::image::Platform;
use sqlx::{Pool, Sqlite};

use crate::{
    management::db::{self, OCI_DB_MIGRATOR},
    oci::{Registry, global_cache::GlobalCache},
};
use tempfile::TempDir;

/// Mock the registry client and sqlite db.
pub(crate) async fn mock_registry_and_db() -> (Registry<GlobalCache>, Pool<Sqlite>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let layers_tar_dir = temp_dir.path().join("download");
    let extracted_layers_dir = temp_dir.path().join("extracted");
    let db_path = temp_dir.path().join("db");
    let db = db::get_or_create_pool(&db_path, &OCI_DB_MIGRATOR)
        .await
        .unwrap();

    OCI_DB_MIGRATOR.run(&db).await.unwrap();

    let platform = Platform::default();
    let layer_ops = GlobalCache::new(layers_tar_dir, extracted_layers_dir, db.clone())
        .await
        .expect("global cache to be initialized");
    let registry = Registry::new(db.clone(), platform, layer_ops)
        .await
        .unwrap();
    (registry, db, temp_dir)
}
