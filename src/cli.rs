use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "crypax")]
#[command(version)]
#[command(about = "Encrypt files or folders into anonymous archive shards")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    Encrypt {
        source: PathBuf,
        output_dir: PathBuf,
    },
    Decrypt {
        archive_dir: PathBuf,
        output_dir: PathBuf,
    },
    Verify {
        archive_dir: PathBuf,
    },
    Repair {
        archive_dir: PathBuf,
    },
    List,
    Forget {
        target: String,
    },
    Meta {
        #[command(subcommand)]
        command: MetaCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum MetaCommand {
    Show {
        target: String,
    },
    Set {
        target: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        custom: Option<String>,
    },
    Thumbnail {
        target: String,
        image_path: PathBuf,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}
