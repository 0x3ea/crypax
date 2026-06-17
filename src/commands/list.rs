use crate::index::{db::IndexDb, models::IndexRecord};

use crate::error::Result;
pub fn run() -> Result<()> {
    let db = IndexDb::open_default()?;
    let records = db.list_records()?;

    if records.is_empty() {
        println!("No archives in index.");
        return Ok(());
    }

    for record in &records {
        println!("{}", format_record(record));
    }

    Ok(())
}
// title should be filename instead?
fn format_record(record: &IndexRecord) -> String {
    let title = record
        .metadata
        .title
        .as_deref()
        .or_else(|| record.archive_path.file_name()?.to_str())
        .unwrap_or("-");

    format!(
        "{id} {fp} {path} {time} {title}",
        id = &record.archive_id[..8],
        fp = &record.fingerprint[..12],
        path = &record.archive_path.display(),
        time = format_timestamp(record.created_at),
        title = title,
    )
}

fn format_timestamp(epoch: i64) -> String {
    let secs = epoch;
    let days = secs / 86400;
    let y = 1970 + (days * 4 + 2) / 1461;
    let doy = days - (365 * (y - 1970) + (y - 1970 + 1) / 4);
    let month_table = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0;
    let mut d = doy;
    for &ml in &month_table {
        if d < ml {
            break;
        }
        d -= ml;
        m += 1;
    }
    format!("{:04}-{:02}-{:02}", y, m + 1, d + 1)
}
