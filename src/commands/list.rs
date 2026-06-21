use crate::commands::format_timestamp;
use crate::index::{db::IndexDb, models::IndexRecord};

use crate::error::Result;
pub fn run() -> Result<()> {
    let db = IndexDb::open_default()?;
    let records = db.list_records()?;

    if records.is_empty() {
        println!("No archives in index.");
        return Ok(());
    }

    println!(
        "{:<8} {:<12} {:<10} {:<10}",
        "ID", "FINGERPRINT", "CREATED", "TITLE"
    );
    for record in &records {
        println!("{}", format_record(record));
    }

    Ok(())
}

fn format_record(record: &IndexRecord) -> String {
    let title = record
        .metadata
        .title
        .as_deref()
        .or_else(|| record.archive_path.file_name()?.to_str())
        .unwrap_or("-");

    format!(
        "{:<8} {:<12} {:<10} {:<10}",
        &record.archive_id[..8],
        &record.fingerprint[..12],
        format_timestamp(record.created_at),
        title,
    )
}
