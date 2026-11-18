//! Single-purpose VM process used only during private restore preparation.

use std::io::Read;
use std::path::Path;

use microsandbox_filesystem::agentd;
use msb_krun::{DiskImageFormat, VmBuilder};

use super::{
    UpperLayerSpec, UpperSpec, attach_upper_layers, bind_rootfs_backend, validate_upper_layers,
};
use crate::launch::RootfsUpperLayerConfig;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Boot the embedded editor with only its scratch directory and staged root disk.
/// The SDK holds stdin open through completion. A caller crash closes it and
/// terminates this process even while the guest is still booting.
#[doc(hidden)]
pub fn enter_snapshot_editor(
    firmware: &Path,
    scratch: &Path,
    chain: &Path,
    lower: Option<&Path>,
) -> RuntimeResult<()> {
    if !agentd::EMBEDDED_DISK_EDITOR {
        return Err(RuntimeError::Custom(
            "upgrade required: this runtime lacks the embedded snapshot disk editor".into(),
        ));
    }
    agentd::initialize_embedded_reader().map_err(|e| RuntimeError::Custom(e.to_string()))?;
    let spec: Vec<RootfsUpperLayerConfig> = serde_json::from_reader(std::fs::File::open(chain)?)?;
    let mut layers = Vec::new();
    for layer in spec {
        let format = match layer.format.as_str() {
            "raw" => DiskImageFormat::Raw,
            "qcow2" => DiskImageFormat::Qcow2,
            other => {
                return Err(RuntimeError::Custom(format!(
                    "unsupported snapshot editor disk format {other}"
                )));
            }
        };
        layers.push(UpperLayerSpec {
            path: layer.path,
            format,
        });
    }
    let layers = validate_upper_layers(&UpperSpec {
        layers,
        read_only: false,
    })?;
    if layers.last().map(|l| l.format) != Some(DiskImageFormat::Qcow2) {
        return Err(RuntimeError::Custom(
            "snapshot editor requires a private qcow2 writable head".into(),
        ));
    }
    let fs = bind_rootfs_backend(
        scratch,
        false,
        microsandbox_protocol::FS_STATE_LIMIT_DEFAULT_MIB as usize * 1024 * 1024,
    )?;
    let mut vm = VmBuilder::new()
        .machine(|m| m.vcpus(1).memory_mib(256))
        .kernel(|k| k.krunfw_path(firmware))
        .fs(|f| f.tag("/dev/root").custom(Box::new(fs)))
        .exec(|e| e.args([microsandbox_protocol::snapshot_patch::BOOT_ARG]));
    #[cfg(windows)]
    {
        // WHP needs the same virtio boot console as a regular sandbox. With
        // only the implicit console the helper can exit before writing its receipt.
        let log = chain.with_file_name("editor-kernel.log");
        vm = vm.console(|c| c.disable_implicit().virtio_output(log));
    }
    if let Some(lower) = lower {
        vm = vm.disk(|d| d.path(lower).format(DiskImageFormat::Vmdk).read_only(true));
    }
    let vm = vm
        .disk(|d| {
            attach_upper_layers(d, layers)
                .format(DiskImageFormat::Qcow2)
                .direct_io(cfg!(target_os = "linux"))
        })
        .build()
        .map_err(|e| RuntimeError::Custom(format!("build editor VM: {e}")))?;
    std::thread::Builder::new()
        .name("snapshot-editor-owner".into())
        .spawn(|| {
            let _ = std::io::stdin().read_exact(&mut [0]);
            std::process::exit(1);
        })?;
    match vm.enter() {
        Ok(never) => match never {},
        Err(e) => Err(RuntimeError::Custom(format!("enter editor VM: {e}"))),
    }
}
