//! `msb context` command — show the active SDK backend without exposing credentials.

use clap::Args;
use microsandbox::BackendInfo;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show the active backend, endpoint, and selection source.
#[derive(Debug, Args)]
pub struct ContextArgs {
    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb context` command.
pub fn run(args: ContextArgs) -> anyhow::Result<()> {
    let info = microsandbox::default_backend_info();
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    render_human(&info).print();
    Ok(())
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
