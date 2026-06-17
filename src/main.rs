use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> crypax::error::Result<()> {
    let cli = crypax::cli::parse();
    crypax::commands::dispatch(cli)
}
