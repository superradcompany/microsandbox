//! Observation under stopped-source lifecycle ownership; never portable snapshot metadata.

use std::path::Path;

#[cfg(unix)]
use std::{collections::BTreeSet, fs::File, os::unix::fs::MetadataExt};

#[cfg(unix)]
use cap_primitives::fs as cap_fs;
#[cfg(unix)]
use microsandbox_filesystem::CapturedRuntimeScripts;
#[cfg(unix)]
use microsandbox_runtime::retention::{CapturedScriptBacking, CapturedScriptDirectory};
use microsandbox_runtime::retention::{ScriptBackingEvidence, ScriptBackingUnknown};
use microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES;

use crate::sandbox::SandboxConfig;
#[cfg(unix)]
use crate::snapshot::saved_config::capture_runtime_scripts;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The enclosing capture owns lifecycle and physical disk authority until finish.
/// A confirmed registration map is required; desired next-start text is never a substitute.
pub(super) enum StoppedScriptObservation {
    Unknown(ScriptBackingUnknown),
    #[cfg(unix)]
    Observed {
        sandbox: File,
        runtime: File,
        scripts: Box<CapturedRuntimeScripts>,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StoppedScriptObservation {
    pub(super) fn observe(directory: &Path, configuration: Option<&SandboxConfig>) -> Self {
        let Some(configuration) = configuration else {
            return Self::Unknown(ScriptBackingUnknown::SourceUnavailable);
        };
        if configuration.spec.runtime.scripts.len() > MAX_SAVED_CONFIG_ENTRIES {
            return Self::Unknown(ScriptBackingUnknown::Unreadable);
        }
        #[cfg(unix)]
        {
            let roots = (|| {
                // Follow the configured parent according to existing home-path policy, but
                // never follow a substituted sandbox or runtime symlink into unrelated files.
                let parent = cap_fs::open_ambient_dir(
                    directory.parent().ok_or_else(|| {
                        std::io::Error::other("missing capture directory component")
                    })?,
                    cap_primitives::ambient_authority(),
                )?;
                let sandbox = cap_fs::open_dir_nofollow(
                    &parent,
                    Path::new(directory.file_name().ok_or_else(|| {
                        std::io::Error::other("missing capture directory component")
                    })?),
                )?;
                let runtime = cap_fs::open_dir_nofollow(&sandbox, Path::new("runtime"))?;
                Ok::<_, std::io::Error>((sandbox, runtime))
            })();
            let Ok((sandbox, runtime)) = roots else {
                return Self::Unknown(ScriptBackingUnknown::BackendUnavailable);
            };
            let names = configuration
                .spec
                .runtime
                .scripts
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let Ok(scripts) = capture_runtime_scripts(&runtime, &names) else {
                return Self::Unknown(ScriptBackingUnknown::Unreadable);
            };
            Self::Observed {
                sandbox,
                runtime,
                scripts: Box::new(scripts),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (directory, configuration);
            Self::Unknown(ScriptBackingUnknown::BackendUnavailable)
        }
    }

    pub(super) fn finish(self) -> ScriptBackingEvidence {
        match self {
            Self::Unknown(reason) => ScriptBackingEvidence::Unknown { reason },
            #[cfg(unix)]
            Self::Observed {
                sandbox,
                runtime,
                scripts,
            } => {
                // Runtime restart is excluded by the enclosing lifecycle guard. Independently
                // detect host namespace replacement rather than observing the new pathname.
                let unchanged = (|| {
                    let current =
                        cap_fs::open_dir_nofollow(&sandbox, Path::new("runtime"))?.metadata()?;
                    let original = runtime.metadata()?;
                    Ok::<_, std::io::Error>(
                        current.dev() == original.dev() && current.ino() == original.ino(),
                    )
                })()
                .unwrap_or(false);
                if !unchanged || scripts.revalidate().is_err() {
                    return ScriptBackingEvidence::Unknown {
                        reason: ScriptBackingUnknown::Changed,
                    };
                }
                let (runtime, directory) = scripts.directory_metadata();
                ScriptBackingEvidence::Observed {
                    runtime_directory: CapturedScriptDirectory {
                        uid: runtime.uid,
                        gid: runtime.gid,
                        mode: runtime.mode,
                    },
                    scripts_directory: CapturedScriptDirectory {
                        uid: directory.uid,
                        gid: directory.gid,
                        mode: directory.mode,
                    },
                    files: scripts
                        .observations()
                        .map(|(name, content, metadata)| {
                            (
                                name.to_owned(),
                                CapturedScriptBacking {
                                    content: content.to_owned(),
                                    uid: metadata.uid,
                                    gid: metadata.gid,
                                    mode: metadata.mode,
                                },
                            )
                        })
                        .collect(),
                }
            }
        }
    }
}
