//! Inspect backend selection and manage saved profiles without exposing credentials.

use clap::{Args, Subcommand};
use microsandbox::{BackendInfo, config::BackendContext};

use crate::ui::{self, OutputFormat};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Inspect or change the selected backend profile.
#[derive(Debug, Args)]
pub struct ContextArgs {
    /// Manage saved profiles without constructing a backend.
    #[command(subcommand)]
    pub command: Option<ContextCommands>,

    /// Output format (json).
    #[arg(long, global = true, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Commands for inspecting profiles and editing the saved user preference.
#[derive(Debug, Subcommand)]
pub enum ContextCommands {
    /// List profiles and their policy status without resolving credentials.
    List,
    /// Save a named profile as the user preference.
    Use {
        /// Existing profile name from user or managed configuration.
        name: String,
    },
    /// Remove the saved user preference.
    Reset,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb context` command.
pub fn run(args: ContextArgs) -> anyhow::Result<()> {
    if let Some(command) = args.command {
        let context = match command {
            ContextCommands::List => BackendContext::load()?,
            ContextCommands::Use { name } => {
                let context = BackendContext::use_profile(&name)?;
                ui::success("Saved profile", &name);
                context
            }
            ContextCommands::Reset => {
                let context = BackendContext::reset()?;
                ui::success("Reset", "saved profile preference");
                context
            }
        };

        if args.format == Some(OutputFormat::Json) {
            println!("{}", serde_json::to_string_pretty(&context)?);
        } else {
            if let Some(selected) = &context.selected {
                println!(
                    "Selected backend: {} ({})",
                    selected.kind.as_str(),
                    selected.source.as_str()
                );
            }
            if context.profiles.is_empty() {
                println!("No profiles configured.");
            } else {
                render_profiles(&context).print();
            }
        }

        if context.preference_overridden {
            ui::warn("Environment or managed settings override the saved profile preference.");
        }
        if let Some(error) = &context.selection_error {
            ui::warn(error);
        }
        return Ok(());
    }

    let info = microsandbox::default_backend_info()?;
    if args.format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    render_human(&info).print();
    Ok(())
}

fn render_profiles(context: &BackendContext) -> ui::Table {
    let mut table = ui::Table::new(&["PROFILE", "BACKEND", "SELECTED", "STATUS"]);
    for profile in &context.profiles {
        let selected = context
            .selected
            .as_ref()
            .and_then(|info| info.profile.as_deref())
            == Some(profile.name.as_str());

        let status = if !profile.allowed {
            "prohibited by policy"
        } else if !profile.available {
            "unavailable in this build"
        } else if !profile.credentials_configured {
            "credential reference missing"
        } else {
            "allowed"
        };

        table.add_row(vec![
            profile.name.clone(),
            profile.kind.as_str().into(),
            if selected { "yes" } else { "" }.into(),
            status.into(),
        ]);
    }

    table
}

fn render_human(info: &BackendInfo) -> ui::Table {
    let mut table = ui::Table::new(&["FIELD", "VALUE"]);
    table.add_row(vec!["Backend".into(), info.kind.as_str().into()]);
    if let Some(api_url) = &info.api_url {
        table.add_row(vec!["API URL".into(), api_url.clone()]);
    }

    table.add_row(vec!["Source".into(), info.source.as_str().into()]);
    if let Some(profile) = &info.profile {
        table.add_row(vec!["Profile".into(), profile.clone()]);
    }

    table
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox::{BackendKind, BackendSelectionSource};

    use super::*;

    fn cloud_info() -> BackendInfo {
        BackendInfo {
            kind: BackendKind::Cloud,
            api_url: Some("https://api.microsandbox.dev".into()),
            source: BackendSelectionSource::MsbApiKey,
            profile: None,
        }
    }

    #[test]
    fn human_context_uses_existing_table_style() {
        let rendered = render_human(&cloud_info()).render();
        assert!(rendered.contains("Backend"));
        assert!(rendered.contains("cloud"));
        assert!(rendered.contains("https://api.microsandbox.dev"));
        assert!(rendered.contains("MSB_API_KEY"));
        assert!(!rendered.contains("msb_ak_"));
    }

    #[test]
    fn json_context_is_structured_and_secret_safe() {
        let rendered = serde_json::to_string(&cloud_info()).unwrap();
        assert_eq!(
            rendered,
            r#"{"kind":"cloud","api_url":"https://api.microsandbox.dev","source":"MSB_API_KEY"}"#
        );
        assert!(!rendered.contains("msb_ak_"));
    }
}
