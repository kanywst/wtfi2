use color_eyre::Result;
use std::io::IsTerminal;
use wtfi2::cli::Cli;
use wtfi2::{diagnose, engine, json, render, ui};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse_args();

    if cli.watch {
        return ui::run().await;
    }

    let path = engine::run_once().await;
    let verdict = diagnose::diagnose(&path);

    if cli.json {
        println!("{}", json::to_string(&path, &verdict));
    } else {
        let color = !cli.no_color && std::io::stdout().is_terminal();
        print!("{}", render::report(&path, &verdict, cli.verbose, color));
    }

    // Exit code reflects health, so scripts can branch on it.
    std::process::exit(match verdict.status {
        wtfi2::model::Status::Ok => 0,
        wtfi2::model::Status::Warn => 1,
        _ => 2,
    });
}
