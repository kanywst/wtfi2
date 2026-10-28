use color_eyre::Result;
use std::io::IsTerminal;
use wtfi2::cli::Cli;
use wtfi2::{diagnose, engine, history, json, platform, recorder, render, ui};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse_args();

    if let Some(n) = cli.history {
        let records = match history::default_path() {
            Some(file) => history::load(&file, n)?,
            None => Vec::new(),
        };
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&records)?);
        } else {
            print!("{}", history::render(&records));
        }
        return Ok(());
    }
    let record_to = cli.record.then(history::default_path).flatten();
    if cli.record && record_to.is_none() {
        eprintln!("wtfi: not recording: set WTFI_HISTORY, XDG_STATE_HOME or HOME");
    }

    // Before the OS check: the demo never touches the platform layer.
    #[cfg(feature = "demo")]
    let demo = match cli.demo.as_deref() {
        None => None,
        Some(v) => match wtfi2::demo::Scenario::parse(v, cli.watch || cli.every.is_some()) {
            Some(s) => Some(s),
            None => {
                eprintln!("wtfi: unknown --demo scenario {v:?} (healthy, dns, isp)");
                std::process::exit(64);
            }
        },
    };
    #[cfg(feature = "demo")]
    if let Some(scenario) = demo
        && cli.watch
    {
        return ui::run_demo(scenario).await;
    }
    #[cfg(not(feature = "demo"))]
    let demo: Option<()> = None;

    // Refuse before probing: every hop would fail and the report would blame the
    // user's network for what is really a missing port. Exits outside the 0/1/2
    // health scale, since this says nothing about the network.
    if let Some(reason) = platform::UNSUPPORTED_OS.filter(|_| demo.is_none()) {
        eprintln!("wtfi: {reason}");
        std::process::exit(3);
    }

    // The demo only records into an explicit WTFI_HISTORY, never the real file.
    #[cfg(feature = "demo")]
    let record_to =
        record_to.filter(|_| demo.is_none() || std::env::var_os("WTFI_HISTORY").is_some());

    if let Some(every) = cli.every {
        let Some(file) = record_to else {
            eprintln!("wtfi: --every needs somewhere to record (set WTFI_HISTORY)");
            std::process::exit(64);
        };
        let deadline = cli.sweep_deadline();
        recorder::run(every, history::Log::open(file), |n| {
            sweep(demo, n, deadline)
        })
        .await;
        return Ok(());
    }

    if cli.watch {
        return ui::run(cli.sweep_deadline(), record_to).await;
    }

    let path = sweep(demo, 0, cli.sweep_deadline()).await;
    let verdict = diagnose::diagnose(&path);

    if let Some(file) = record_to
        && let Err(e) = history::Log::open(file.clone()).push(
            &history::Record::now(&path, &verdict),
            json::to_value(&path, &verdict),
        )
    {
        eprintln!("wtfi: could not record to {}: {e}", file.display());
    }

    if cli.json {
        println!("{}", json::to_string(&path, &verdict));
    } else {
        let tty = std::io::stdout().is_terminal();
        let color = !cli.no_color && tty;
        // Wrap to the terminal; leave lines whole for a pipe.
        let width = tty
            .then(crossterm::terminal::size)
            .and_then(Result::ok)
            .map(|(cols, _)| usize::from(cols));
        print!(
            "{}",
            render::report_to_width(&path, &verdict, cli.verbose, color, width)
        );
    }

    // Exit code reflects health, so scripts can branch on it. "Nothing could
    // be measured" gets its own code: it is not a clean bill of health, but it
    // is not an observed outage either, and a script that retries on 4 would
    // be wrong to give up on 2.
    std::process::exit(match verdict.status {
        wtfi2::model::Status::Ok => 0,
        wtfi2::model::Status::Warn => 1,
        wtfi2::model::Status::Skipped => 4,
        _ => 2,
    });
}

#[cfg(feature = "demo")]
async fn sweep(
    demo: Option<wtfi2::demo::Scenario>,
    n: usize,
    deadline: std::time::Duration,
) -> wtfi2::model::Path {
    match demo {
        Some(scenario) => wtfi2::demo::run_sweep(scenario, n).await,
        None => engine::run_once_within(deadline).await,
    }
}

#[cfg(not(feature = "demo"))]
async fn sweep(_: Option<()>, _: usize, deadline: std::time::Duration) -> wtfi2::model::Path {
    engine::run_once_within(deadline).await
}
