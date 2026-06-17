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
