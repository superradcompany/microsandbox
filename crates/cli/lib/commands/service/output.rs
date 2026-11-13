//! Human and JSON output for `msb service`.

use microsandbox::{CloudService, CloudServiceStatus, Service, ServiceTarget};

use crate::ui::{self, OutputFormat};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The Service's fields as the public REST body, so JSON output matches the API.
pub(super) fn service_record(service: &Service) -> CloudService {
    CloudService {
        slug: service.slug().to_string(),
        url: service.url().to_string(),
        status: service.status(),
        target: service.target(),
        created_at: service.created_at(),
        updated_at: service.updated_at(),
    }
}

pub(super) fn print_service(service: &Service, format: Option<OutputFormat>) -> anyhow::Result<()> {
    let record = service_record(service);

    if format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }

    ui::detail_kv("Slug", &record.slug);
    ui::detail_kv("URL", &record.url);
    ui::detail_kv("Status", status_label(record.status));
    ui::detail_kv("Target", &target_label(record.target.as_ref()));
    ui::detail_kv("Created", &ui::format_datetime(&record.created_at));
    ui::detail_kv("Updated", &ui::format_datetime(&record.updated_at));
    Ok(())
}

pub(super) fn service_table(records: &[CloudService]) -> ui::Table {
    let mut table = ui::Table::new(&["SLUG", "STATUS", "TARGET", "URL"]);
    for record in records {
        table.add_row(vec![
            record.slug.clone(),
            status_label(record.status).to_string(),
            target_label(record.target.as_ref()),
            record.url.clone(),
        ]);
    }
    table
}

fn target_label(target: Option<&ServiceTarget>) -> String {
    match target {
        Some(target) => format!("{}:{}", target.sandbox, target.port),
        None => "-".to_string(),
    }
}

fn status_label(status: CloudServiceStatus) -> &'static str {
    status.as_str()
}
