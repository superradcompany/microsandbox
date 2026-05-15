//! Disk image volume — attach raw and qcow2 host images at guest paths.

use std::path::PathBuf;

use microsandbox::{Sandbox, sandbox::DiskImageFormat};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sample-images");
    let raw_path = data_dir.join("ext4-seeded.raw");
    let qcow2_path = data_dir.join("ext4-seeded.qcow2");

    let sandbox = Sandbox::builder("volume-disk")
        .image("alpine")
        .volume("/seed", |v| {
            v.disk(&raw_path)
                .format(DiskImageFormat::Raw)
                .fstype("ext4")
                .readonly()
        })
        .volume("/data", |v| {
            v.disk(&qcow2_path)
                .format(DiskImageFormat::Qcow2)
                .fstype("ext4")
        })
        .replace()
        .create()
        .await?;

    let seed = sandbox.shell("cat /seed/hello.txt").await?;
    println!("{}", seed.stdout()?);

    sandbox
        .shell("echo 'written from sandbox' > /data/created.txt")
        .await?;
    let back = sandbox.shell("cat /data/created.txt").await?;
    println!("{}", back.stdout()?);

    sandbox.stop_and_wait().await?;
    Ok(())
}
