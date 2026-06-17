use std::{fs, path::Path};

use crate::index::db::{IndexDb, default_index_dir};

use crate::{cli::MetaCommand, error::Result};
pub fn run(command: MetaCommand) -> Result<()> {
    match command {
        MetaCommand::Set {
            target,
            title,
            note,
            tag,
            custom,
        } => run_set(target, title, note, tag, custom),
        MetaCommand::Show { target } => run_show(&target),
        MetaCommand::Thumbnail { target, image_path } => run_thumbnail(target, &image_path),
    }
}
fn run_set(
    target: String,
    title: Option<String>,
    note: Option<String>,
    tags: Vec<String>,
    custom: Option<String>,
) -> Result<()> {
    let db = IndexDb::open_default()?;
    let mut record = db
        .find_by_target(&target)?
        .ok_or_else(|| anyhow::anyhow!("no archive found matching '{}'", target))?;

    if let Some(t) = title {
        record.metadata.title = Some(t);
    }
    if let Some(n) = note {
        record.metadata.note = Some(n);
    }
    if !tags.is_empty() {
        for tag in tags {
            if !record.metadata.tags.contains(&tag) {
                record.metadata.tags.push(tag);
            }
        }
    }

    if let Some(c) = custom {
        let value: serde_json::Value = serde_json::from_str(&c)
            .map_err(|e| anyhow::anyhow!("invalid JSON for --custom: {}", e))?;
        record.metadata.custom = Some(value);
    }
    db.update_metadata(&target, &record.metadata)?;
    println!("Updated metadata for '{}'.", target);
    Ok(())
}
fn run_show(target: &str) -> Result<()> {
    let db = IndexDb::open_default()?;
    let record = db
        .find_by_target(target)?
        .ok_or_else(|| anyhow::anyhow!("no archive found matching '{}'", target))?;

    println!("Archive ID:   {}", record.archive_id);
    println!("Fingerprint:  {}", record.fingerprint);
    println!("Path:         {}", record.archive_path.display());
    println!("Created:      {}", record.created_at);
    if let Some(title) = &record.metadata.title {
        println!("Title:        {}", title);
    }
    if let Some(note) = &record.metadata.note {
        println!("Note:         {}", note);
    }
    if !record.metadata.tags.is_empty() {
        println!("Tags:         {}", record.metadata.tags.join(", "));
    }
    if let Some(custom) = &record.metadata.custom {
        println!("Custom:       {}", custom);
    }
    if let Some(thumb) = &record.metadata.thumbnail {
        println!("Thumbnail:    {}", thumb);
    }
    Ok(())
}

fn run_thumbnail(target: String, image_path: &Path) -> Result<()> {
    if !image_path.exists() {
        anyhow::bail!("image not found: {}", image_path.display());
    }

    let db = IndexDb::open_default()?;
    let mut record = db
        .find_by_target(&target)?
        .ok_or_else(|| anyhow::anyhow!("no archive found matching '{}'", target))?;

    let index_dir = default_index_dir()?;
    let thumb_dir = index_dir.join("thumbnails");
    fs::create_dir_all(&thumb_dir)?;

    let ext = image_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");

    let dest = thumb_dir.join(format!("{}.{}", record.archive_id, ext));
    fs::copy(image_path, &dest)?;

    record.metadata.thumbnail = Some(dest.to_string_lossy().into_owned());
    db.update_metadata(&target, &record.metadata)?;

    println!("Thumbail set for '{}'.", target);
    Ok(())
}
