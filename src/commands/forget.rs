use crate::index::db::IndexDb;
use anyhow::Ok;

use crate::error::Result;
pub fn run(target: String) -> Result<()> {
    let db = IndexDb::open_default()?;

    let deleted = db.delete_by_target(&target)?;

    if deleted {
        println!("Removed archive record for '{}'", target);
    } else {
        anyhow::bail!("no archive found matching '{}'", target);
    }
    Ok(())
}
