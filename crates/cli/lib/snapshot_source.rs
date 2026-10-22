//! Canonical snapshot launch selectors shared by `create` and `run`.
//!
//! Classification is lexical: a missing path never becomes a group lookup, and an
//! archive suffix never turns a bare group name into a host path.

use std::path::{Path, PathBuf};

use clap::Args;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Source selection for the canonical snapshot-backed launch commands.
#[derive(Debug, Default, Clone, Args)]
pub struct SnapshotSourceArgs {
    /// One installed group or one or more explicit archive/artifact paths.
    ///
    /// Use ./backup.msb for a path; bare backup.msb means a group. For run, place
    /// the guest command after --. Paths form a dependency set, not a sequence.
    #[arg(long = "from-snapshot", visible_alias = "from-snap", num_args = 1.., value_name = "GROUP_OR_PATH", conflicts_with = "image")]
    pub sources: Vec<String>,

    /// Select one member in the group, or an exact checkpoint ID in the path set.
    #[arg(long, value_name = "MEMBER_OR_ID")]
    pub checkpoint: Option<String>,

    /// Cold-boot the disk of a full checkpoint instead of resuming its processes.
    #[arg(long, conflicts_with_all = ["image", "cow_memory", "forked"])]
    pub disk_only: bool,

    /// Restore full checkpoint memory with private copy-on-write mappings.
    #[arg(long = "cow-mem", conflicts_with = "image")]
    pub cow_memory: bool,

    /// Deprecated alias for --cow-mem.
    #[arg(long, hide = true, conflicts_with = "image")]
    pub forked: bool,

    /// Permit unavailable captured external resources; never waive required snapshot data.
    #[arg(long, conflicts_with = "image")]
    pub allow_missing_resources: bool,

    /// Reuse unspecified bindings only from validated source-local records.
    #[arg(long, conflicts_with = "image")]
    pub dangerously_inherit_resources: bool,

    /// Validate supplied external objects strictly or tolerate supported stale-object mismatches.
    #[arg(long, value_parser = ["strict", "relaxed"], conflicts_with = "image")]
    pub external_mount_policy: Option<String>,
}

/// An unambiguous source interpretation, before any filesystem or catalog work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotLaunchSource {
    /// A named installed group, with its head or one explicit member selected.
    Group {
        /// The supplied group name; never a legacy colon or cloud reference.
        name: String,
        /// An optional member name or immutable checkpoint ID.
        checkpoint: Option<String>,
    },
    /// Explicit paths whose identities and dependencies must be resolved together.
    Paths {
        /// Paths in user order for diagnostics only; order does not select a target.
        paths: Vec<PathBuf>,
        /// An exact checkpoint ID when the set has more than one terminal member.
        checkpoint: Option<String>,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotSourceArgs {
    /// Apply one shared source path after configuration and before launch options.
    pub async fn apply(
        &self,
        configured: &crate::sandbox_config::ResolvedSandboxConfig,
        image: Option<&str>,
        builder: microsandbox::sandbox::SandboxBuilder,
    ) -> anyhow::Result<(microsandbox::sandbox::SandboxBuilder, String)> {
        let Some(source) = self.resolve(configured.snapshot_source(), image.is_some())? else {
            let image = configured.image(image, None)?;
            return Ok((image.apply(builder)?, image.display()));
        };
        let (builder, label) = match source {
            SnapshotLaunchSource::Group { name, checkpoint } => {
                let member = open_group_checkpoint(&name, checkpoint.as_deref()).await?;
                (builder.override_snapshot_member(&member), name)
            }
            source @ SnapshotLaunchSource::Paths { .. } => {
                let SnapshotLaunchSource::Paths { paths, checkpoint } =
                    source.anchor_paths(&std::env::current_dir()?)?
                else {
                    unreachable!()
                };
                let label = paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let checkpoint = checkpoint
                    .map(microsandbox::snapshot::SnapshotId::new)
                    .transpose()?;
                (builder.override_snapshot_paths(paths, checkpoint), label)
            }
        };
        if self.forked {
            crate::ui::warn("--forked is deprecated; use --cow-mem instead");
        }
        let policy = self.external_mount_policy.as_deref().map(|policy| {
            if policy == "relaxed" {
                microsandbox::sandbox::ExternalMountRestorePolicy::Relaxed
            } else {
                microsandbox::sandbox::ExternalMountRestorePolicy::Strict
            }
        });
        let builder = builder
            .snapshot_launch_options(self.disk_only, self.cow_memory || self.forked)
            .snapshot_resource_options(
                self.allow_missing_resources,
                self.dangerously_inherit_resources,
                policy,
            );
        Ok((builder, label))
    }

    /// Resolve CLI precedence over a configured source without inspecting host files.
    ///
    /// A positional image conflicts with an explicit snapshot source in clap. A
    /// snapshot source supplied only by configuration may still be overridden by an
    /// explicit image, following the existing file/flag precedence.
    pub fn resolve(
        &self,
        configured_snapshot: Option<&str>,
        explicit_image: bool,
    ) -> anyhow::Result<Option<SnapshotLaunchSource>> {
        if explicit_image && !self.sources.is_empty() {
            anyhow::bail!("an image cannot be combined with --from-snapshot");
        }
        let inputs: Vec<&str> = if !self.sources.is_empty() {
            self.sources.iter().map(String::as_str).collect()
        } else if !explicit_image {
            configured_snapshot.into_iter().collect()
        } else {
            Vec::new()
        };
        if inputs.is_empty() {
            anyhow::ensure!(
                self.checkpoint.is_none()
                    && !self.disk_only
                    && !self.cow_memory
                    && !self.forked
                    && !self.allow_missing_resources
                    && !self.dangerously_inherit_resources
                    && self.external_mount_policy.is_none(),
                "snapshot selection, mode and resource controls require a snapshot source from --from-snapshot or configuration"
            );
            return Ok(None);
        }
        if let Some(member) = &self.checkpoint {
            anyhow::ensure!(
                !member.is_empty()
                    && !member.contains(['/', '\\', ':'])
                    && !member.starts_with('.'),
                "--checkpoint must be a group member name or checkpoint ID, not a path or colon selector"
            );
        }
        let path_count = inputs.iter().filter(|input| explicit_path(input)).count();
        if path_count == inputs.len() {
            return Ok(Some(SnapshotLaunchSource::Paths {
                paths: inputs.into_iter().map(PathBuf::from).collect(),
                checkpoint: self.checkpoint.clone(),
            }));
        }
        anyhow::ensure!(
            path_count == 0 && inputs.len() == 1,
            "use exactly one snapshot group or only explicit paths; prefix a relative path with ./"
        );
        let name = inputs[0];
        anyhow::ensure!(
            !name.is_empty() && !name.starts_with('.') && !name.contains(':'),
            "invalid snapshot group {name:?}; select a member with --checkpoint, or use an explicit path"
        );
        Ok(Some(SnapshotLaunchSource::Group {
            name: name.into(),
            checkpoint: self.checkpoint.clone(),
        }))
    }
}

impl SnapshotLaunchSource {
    /// Anchor native host paths before an asynchronous launch can outlive its cwd.
    /// Preserve symlinks and parent components; do not canonicalize source input.
    pub fn anchor_paths(self, cwd: &Path) -> anyhow::Result<Self> {
        match self {
            Self::Group { .. } => Ok(self),
            Self::Paths { paths, checkpoint } => {
                anyhow::ensure!(
                    cwd.is_absolute(),
                    "snapshot source base directory must be absolute"
                );
                let paths = paths
                    .into_iter()
                    .map(|path| {
                        // Foreign Windows paths must not accidentally become Unix filenames
                        // below cwd. Native Windows handles drive and UNC roots itself.
                        #[cfg(not(windows))]
                        anyhow::ensure!(
                            !windows_root(&path.to_string_lossy()),
                            "Windows snapshot path {} requires a Windows host",
                            path.display()
                        );
                        Ok(if path.is_absolute() {
                            path
                        } else {
                            cwd.join(path)
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok(Self::Paths { paths, checkpoint })
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve the group selection once to an exact checkpoint receiver.
/// Child preparation must validate and pin this identity before consuming payloads;
/// the metadata receiver itself is not a lifetime lease. A cleared head never guesses.
pub async fn open_group_checkpoint(
    name: &str,
    checkpoint: Option<&str>,
) -> anyhow::Result<microsandbox::snapshot::Checkpoint> {
    let group = microsandbox::snapshot::Snapshot::get(name).await?;
    match checkpoint {
        Some(member) => Ok(group.get_checkpoint(member).await?),
        None => group.head().await?.ok_or_else(|| {
            anyhow::anyhow!("snapshot group {name:?} has no selected head; use --checkpoint MEMBER")
        }),
    }
}

pub(crate) fn windows_root(input: &str) -> bool {
    let bytes = input.as_bytes();
    input.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

pub(crate) fn explicit_path(input: &str) -> bool {
    input == "."
        || input == ".."
        || input.contains('/')
        || input.contains('\\')
        || windows_root(input)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser, Subcommand};

    use crate::commands::{create::CreateArgs, run::RunArgs};

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Debug, Subcommand)]
    enum Command {
        Create(CreateLaunch),
        Run(RunLaunch),
    }

    #[derive(Debug, Args)]
    struct CreateLaunch {
        #[command(flatten)]
        args: CreateArgs,
    }

    #[derive(Debug, Args)]
    struct RunLaunch {
        #[command(flatten)]
        args: RunArgs,
    }

    fn resolve(values: &[&str]) -> anyhow::Result<SnapshotLaunchSource> {
        SnapshotSourceArgs {
            sources: values.iter().map(|value| (*value).into()).collect(),
            checkpoint: None,
            ..Default::default()
        }
        .resolve(None, false)
        .map(Option::unwrap)
    }

    #[test]
    fn resource_controls_require_a_selected_snapshot() {
        for controls in [
            SnapshotSourceArgs {
                allow_missing_resources: true,
                ..Default::default()
            },
            SnapshotSourceArgs {
                dangerously_inherit_resources: true,
                ..Default::default()
            },
            SnapshotSourceArgs {
                external_mount_policy: Some("relaxed".into()),
                ..Default::default()
            },
            SnapshotSourceArgs {
                forked: true,
                ..Default::default()
            },
        ] {
            assert!(controls.resolve(None, false).is_err());
            assert!(controls.resolve(Some("history"), false).unwrap().is_some());
            assert!(controls.resolve(Some("history"), true).is_err());
        }
    }

    #[test]
    fn bare_names_never_depend_on_extensions_or_existence() {
        for name in ["templates", "backup.msb", "backup.tar.zst", "snap_123"] {
            assert_eq!(
                resolve(&[name]).unwrap(),
                SnapshotLaunchSource::Group {
                    name: name.into(),
                    checkpoint: None,
                }
            );
        }
        for path in [
            "./templates",
            "../backup",
            "/no-such-file",
            "a/b",
            ".",
            "..",
            r"C:\saved state\backup.msb",
            "C:/backup",
            r"\\server\share\backup",
            r".\backup",
        ] {
            assert_eq!(
                resolve(&[path]).unwrap(),
                SnapshotLaunchSource::Paths {
                    paths: vec![PathBuf::from(path)],
                    checkpoint: None,
                }
            );
        }
    }

    #[test]
    fn group_and_path_sets_are_exclusive() {
        for inputs in [
            &["one", "two"][..],
            &["one", "./two"],
            &["./one", "two"],
            &["history:ready"],
            &["C:relative"],
            &[""],
        ] {
            assert!(resolve(inputs).is_err(), "{inputs:?}");
        }
        let values = ["./later.msb", "./base.msb", "./later.msb"];
        assert_eq!(
            resolve(&values).unwrap(),
            SnapshotLaunchSource::Paths {
                paths: values.into_iter().map(PathBuf::from).collect(),
                checkpoint: None,
            }
        );
    }

    #[test]
    fn source_precedence_and_selector_validation_are_explicit() {
        let mut args = SnapshotSourceArgs::default();
        assert_eq!(
            args.resolve(Some("configured"), false).unwrap(),
            Some(resolve(&["configured"]).unwrap())
        );
        assert_eq!(args.resolve(Some("configured"), true).unwrap(), None);
        args.sources = vec!["explicit".into()];
        assert_eq!(
            args.resolve(Some("configured"), false).unwrap(),
            Some(resolve(&["explicit"]).unwrap())
        );
        assert!(args.resolve(None, true).is_err());
        args.sources.clear();
        args.checkpoint = Some("ready".into());
        assert!(args.resolve(None, false).is_err());
        assert!(args.resolve(Some("configured"), false).is_ok());
        for invalid in ["", "./ready", "history:ready", r"a\b"] {
            args.checkpoint = Some(invalid.into());
            assert!(args.resolve(Some("configured"), false).is_err());
        }
    }

    #[test]
    fn both_commands_preserve_option_and_guest_command_boundaries() {
        // Use the production argument sets so aliases, positionals and flattened
        // destination flags cannot accidentally conflict with source selection.
        Cli::command().debug_assert();
        for command in ["create", "run"] {
            for flag in ["--from-snapshot", "--from-snap"] {
                let mut input = vec![
                    "msb",
                    command,
                    flag,
                    "./base.msb",
                    "./tip.msb",
                    "--checkpoint",
                    "snap_123",
                    "--name",
                    "child",
                ];
                if command == "run" {
                    input.extend(["--", "echo", "--from-snapshot", "guest-value"]);
                }
                let parsed = Cli::try_parse_from(input).unwrap();
                let (source, name) = match parsed.command {
                    Command::Create(launch) => (launch.args.snapshot, launch.args.sandbox.name),
                    Command::Run(launch) => {
                        assert_eq!(
                            launch.args.command,
                            ["echo", "--from-snapshot", "guest-value"]
                        );
                        (launch.args.snapshot, launch.args.sandbox.name)
                    }
                };
                assert_eq!(source.sources, ["./base.msb", "./tip.msb"]);
                assert_eq!(source.checkpoint.as_deref(), Some("snap_123"));
                assert_eq!(name.as_deref(), Some("child"));
                assert!(Cli::try_parse_from(["msb", command, "alpine", flag, "history"]).is_err());
                assert!(Cli::try_parse_from(["msb", command, flag]).is_err());
            }
        }
        assert!(
            Cli::try_parse_from([
                "msb",
                "create",
                "--from-snapshot",
                "history",
                "--",
                "echo",
                "guest-value",
            ])
            .is_err()
        );
    }

    #[test]
    fn paths_are_anchored_without_rewriting_symlink_parent_components() {
        let cwd = std::env::current_dir().unwrap();
        let expected = cwd.join("./link/../checkpoint");
        let selected = resolve(&["./link/../checkpoint"])
            .unwrap()
            .anchor_paths(&cwd)
            .unwrap();
        assert_eq!(
            selected,
            SnapshotLaunchSource::Paths {
                paths: vec![expected],
                checkpoint: None
            }
        );
        assert!(
            resolve(&["./backup"])
                .unwrap()
                .anchor_paths(Path::new("relative"))
                .is_err()
        );
        assert!(resolve(&["history"]).unwrap().anchor_paths(&cwd).is_ok());

        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            let invocation = temp.path().join("invocation");
            let target_parent = temp.path().join("target");
            std::fs::create_dir(&invocation).unwrap();
            std::fs::create_dir_all(target_parent.join("nested")).unwrap();
            std::fs::write(invocation.join("checkpoint"), b"wrong source").unwrap();
            std::fs::write(target_parent.join("checkpoint"), b"selected source").unwrap();
            std::os::unix::fs::symlink(target_parent.join("nested"), invocation.join("link"))
                .unwrap();
            let SnapshotLaunchSource::Paths { paths, .. } = resolve(&["./link/../checkpoint"])
                .unwrap()
                .anchor_paths(&invocation)
                .unwrap()
            else {
                panic!("explicit path must remain a path");
            };
            // No process cwd change: consumption in this unrelated cwd must reach
            // the symlink target's parent, not the lexically collapsed invocation path.
            assert_eq!(std::fs::read(&paths[0]).unwrap(), b"selected source");
        }
    }

    #[tokio::test]
    async fn group_selection_stays_exact_across_head_changes_and_refuses_missing_heads() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use microsandbox::snapshot::{
            DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef,
            LayerFileKind, LayerPayload, Manifest, SnapshotCapture, SnapshotConsistency,
            SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState,
        };

        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("snapshots").join("history");
        std::fs::create_dir_all(&directory).unwrap();
        let ids: Vec<_> = (1..=2)
            .map(|i| SnapshotId::new(format!("snap_{i:032x}")).unwrap())
            .collect();
        for (i, id) in ids.iter().enumerate() {
            let layer = DiskLayerId::new(format!("layer_{:032x}", i + 1)).unwrap();
            let manifest = Manifest {
                schema: "microsandbox.snapshot/1".into(),
                snapshot_id: id.clone(),
                scope: SnapshotScope::Disk,
                state: SnapshotState::File(FileSnapshotState {
                    disk_format: SnapshotFormat::Raw,
                    filesystem: "ext4".into(),
                    virtual_size: 5,
                    head: layer.clone(),
                    layers: vec![DiskLayer {
                        layer_id: layer,
                        format: SnapshotFormat::Raw,
                        virtual_size: 5,
                        backing: None,
                        payload: LayerPayload {
                            file_kind: LayerFileKind::Regular,
                            integrity: None,
                        },
                    }],
                }),
                capture: SnapshotCapture {
                    created_at: "2026-10-19T00:00:00Z".into(),
                    source_lineage: None,
                    source_checkpoint: None,
                    consistency: SnapshotConsistency::CrashConsistent,
                },
                image: ImageRef {
                    reference: "alpine:3.19".into(),
                    manifest_digest: format!("sha256:{}", "a".repeat(64)),
                },
                root_disk: SnapshotRootDisk::Managed,
                parent: None,
                extensions: BTreeMap::new(),
                requires: Vec::new(),
            };
            let member = directory.join(id.as_str());
            std::fs::create_dir(&member).unwrap();
            std::fs::write(
                member.join(DESCRIPTOR_FILENAME),
                manifest.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            let SnapshotState::File(state) = &manifest.state else {
                unreachable!()
            };
            let payload = member.join(state.layer_path(&state.layers[0]));
            std::fs::create_dir_all(payload.parent().unwrap()).unwrap();
            std::fs::write(payload, b"valid").unwrap();
        }
        std::fs::write(
            directory.join("group.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "microsandbox.snapshot-group/1", "head": ids[0].as_str()
            }))
            .unwrap(),
        )
        .unwrap();
        let backend: Arc<dyn microsandbox::Backend> = Arc::new(
            microsandbox::LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .unwrap(),
        );
        microsandbox::backend::with_backend(backend, async {
            let selected = open_group_checkpoint("history", None).await.unwrap();
            assert_eq!(selected.id(), &ids[0]);
            let group = microsandbox::snapshot::Snapshot::get("history")
                .await
                .unwrap();
            group.set_head(ids[1].as_str()).await.unwrap();
            assert_eq!(selected.id(), &ids[0]);
            assert_eq!(
                open_group_checkpoint("history", None).await.unwrap().id(),
                &ids[1]
            );
            group.clear_head().await.unwrap();
            assert!(
                open_group_checkpoint("history", None)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("no selected head")
            );
            assert_eq!(
                open_group_checkpoint("history", Some(ids[0].as_str()))
                    .await
                    .unwrap()
                    .id(),
                &ids[0]
            );
            assert!(
                open_group_checkpoint("history", Some("missing"))
                    .await
                    .is_err()
            );
            assert!(open_group_checkpoint("missing", None).await.is_err());
        })
        .await;
    }
}
