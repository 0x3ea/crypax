mod decrypt;
mod encrypt;
mod forget;
mod list;
mod meta;
mod repair;
mod verify;

use crate::cli::{Cli, Command};
use crate::error::Result;

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Encrypt { source, output_dir } => encrypt::run(source, output_dir),
        Command::Decrypt {
            archive_dir,
            output_dir,
        } => decrypt::run(&archive_dir, &output_dir),
        Command::Verify { archive_dir } => {
            let report = verify::run(archive_dir)?;
            if report.is_healthy() {
                println!("Archive is healthy.");
            } else {
                println!("Found {} issue(s).", report.findings.len());
            }
            Ok(())
        }
        Command::Repair { archive_dir } => repair::run(archive_dir),
        Command::List => list::run(),
        Command::Forget { target } => forget::run(target),
        Command::Meta { command } => meta::run(command),
    }
}

pub fn format_timestamp(epoch: i64) -> String {
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
