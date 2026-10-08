//! Sandbox-scoped job operations, backed by the public Rust SDK.

use std::io::{IsTerminal, Read, Write};

use clap::Args;
use microsandbox::Sandbox;
use microsandbox::jobs::{Job, JobEvent, JobId};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// List jobs owned by one sandbox.
#[derive(Debug, Args)]
pub struct JobsArgs {
    /// Owning sandbox.
    pub name: String,
    /// Include retained completed jobs.
    #[arg(short = 'a', long)]
    pub all: bool,
    /// Maximum entries per page.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Continue after the cursor from a previous page.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Output format.
    #[arg(long, value_parser = ["json"])]
    pub format: Option<String>,
}

/// Select exactly one sandbox-scoped job.
#[derive(Debug, Args)]
pub struct JobArgs {
    /// Owning sandbox.
    pub name: String,
    /// Managed job identity.
    #[arg(long)]
    pub job: String,
}

/// Attach without starting another command.
#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Sandbox and job selection.
    #[command(flatten)]
    pub target: JobArgs,
    /// Observe output without acquiring input.
    #[arg(long)]
    pub read_only: bool,
}

/// Send a signal to a job's process group.
#[derive(Debug, Args)]
pub struct SignalArgs {
    /// Sandbox and job selection.
    #[command(flatten)]
    pub target: JobArgs,
    /// Linux signal name (TERM, INT, HUP, KILL, USR1, USR2, STOP, CONT) or number.
    #[arg(long)]
    pub signal: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn get(name: &str, id: &str) -> anyhow::Result<Job> {
    Ok(Sandbox::get(name).await?.get_job(id).await?)
}

/// Render one list page without acquiring a sandbox lifecycle owner.
pub async fn list(args: JobsArgs) -> anyhow::Result<()> {
    let cursor = args
        .cursor
        .map(JobId::parse)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let page = Sandbox::get(&args.name)
        .await?
        .list_jobs_with(|options| {
            let options = options.all(args.all).limit(args.limit);
            match cursor {
                Some(cursor) => options.cursor(cursor),
                None => options,
            }
        })
        .await?;
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(&page)?);
    } else {
        println!("{:<36}  {:<10}  COMMAND", "JOB", "STATE");
        for job in page.items {
            println!(
                "{:<36}  {:<10}  {}",
                job.id,
                format!("{:?}", job.state).to_lowercase(),
                job.command.join(" ")
            );
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!(
                "More jobs: msb jobs {} --cursor {}{}",
                args.name,
                cursor,
                if args.all { " --all" } else { "" }
            );
        }
    }
    Ok(())
}

/// Inspect retained job metadata.
pub async fn inspect(name: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let info = get(name, id).await?.inspect().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!(
            "Job:     {}\nSandbox: {}\nState:   {:?}\nCommand: {}\nTTY:     {}\nStdin:   {}",
            info.id,
            name,
            info.state,
            info.command.join(" "),
            info.tty,
            if info.stdin_closed { "closed" } else { "open" }
        );
        if let Some(pid) = info.pid {
            println!("PID:     {pid}");
        }
        if let Some(code) = info.exit_code {
            println!("Exit:    {code}");
        }
        if let Some(error) = info.error {
            println!("Detail:  {error}");
        }
        if let Some(failure) = info.failure {
            println!("Failure: {}", failure.message);
        }
    }
    Ok(())
}

/// Wait without consuming output or terminating a command on wait timeout.
pub async fn wait(name: &str, id: &str, timeout: Option<&str>, json: bool) -> anyhow::Result<()> {
    let job = get(name, id).await?;
    let result = if let Some(timeout) = timeout {
        tokio::time::timeout(super::common::parse_duration(timeout)?, job.wait())
            .await
            .map_err(|_| {
                anyhow::anyhow!("timed out waiting for job {id}; the job was not terminated")
            })??
    } else {
        job.wait().await?
    };
    if json {
        println!("{}", serde_json::to_string(&result)?);
    }
    if result.code != 0 {
        std::process::exit(result.code);
    }
    Ok(())
}

/// Connect a terminal or redirected I/O to an existing job.
pub async fn attach(args: AttachArgs) -> anyhow::Result<()> {
    let job = get(&args.target.name, &args.target.job).await?;
    let attachment = job
        .attach_with(|options| options.read_only(args.read_only))
        .await?;
    let code = if std::io::stdin().is_terminal() {
        attachment.interact_terminal().await?
    } else {
        // Match the existing CLI's bounded stdin reader. Tokio stdin can keep runtime shutdown
        // blocked forever on an open pipe; a detached OS reader does not prevent CLI exit.
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        if !args.read_only {
            std::thread::Builder::new()
                .name("msb-job-stdin".into())
                .spawn(move || {
                    let mut input = std::io::stdin().lock();
                    let mut buffer = [0; 8192];
                    loop {
                        let result = match input.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => Ok(buffer[..n].to_vec()),
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(error) => Err(error),
                        };
                        let failed = result.is_err();
                        if sender.blocking_send(result).is_err() || failed {
                            break;
                        }
                    }
                })?;
        }
        let writer = async {
            if args.read_only {
                std::future::pending::<()>().await;
            }
            while let Some(input) = receiver.recv().await {
                attachment.write_stdin(input?).await?;
            }
            // Host EOF preserves runtime input and leaves output/interrupt handling alive.
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        tokio::pin!(writer);
        loop {
            tokio::select! {
                result = &mut writer => { result?; break None; },
                event = attachment.recv() => match event? {
                    Some(JobEvent::Output(entry)) => {
                        if entry.source == "stderr" { let mut out = std::io::stderr().lock(); out.write_all(&entry.data)?; out.flush()?; }
                        else { let mut out = std::io::stdout().lock(); out.write_all(&entry.data)?; out.flush()?; }
                    }
                    Some(JobEvent::Gap { .. }) => eprintln!("[job output was pruned before replay]"),
                    Some(JobEvent::Completed(info)) => {
                        anyhow::ensure!(info.exit_code.is_some(), "job ended without a confirmed exit: {}", info.error.unwrap_or_else(|| format!("{:?}", info.state)));
                        break info.exit_code;
                    },
                    None => break None,
                    _ => {},
                },
                _ = tokio::signal::ctrl_c() => { attachment.detach().await?; break None; }
            }
        }
    };
    attachment.detach().await?;
    if let Some(code) = code
        && code != 0
    {
        std::process::exit(code);
    }
    Ok(())
}

/// Send an explicit Linux guest signal.
pub async fn signal(args: SignalArgs) -> anyhow::Result<()> {
    get(&args.target.name, &args.target.job)
        .await?
        .signal(parse_signal(&args.signal)?)
        .await?;
    Ok(())
}

/// Request immediate process-group termination.
pub async fn kill(args: JobArgs) -> anyhow::Result<()> {
    get(&args.name, &args.job).await?.kill().await?;
    Ok(())
}

/// Finish the job's pipe input.
pub async fn eof(args: JobArgs) -> anyhow::Result<()> {
    get(&args.name, &args.job).await?.eof().await?;
    Ok(())
}

fn parse_signal(value: &str) -> anyhow::Result<i32> {
    let name = value.to_ascii_uppercase();
    let name = name.strip_prefix("SIG").unwrap_or(&name);
    // Signals target Linux guests even when the CLI runs on macOS or Windows.
    let signal = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "KILL" => 9,
        "USR1" => 10,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        _ => name
            .parse::<i32>()
            .map_err(|_| anyhow::anyhow!("unknown Linux guest signal {value:?}"))?,
    };
    anyhow::ensure!(
        (1..=64).contains(&signal),
        "signal must be between 1 and 64"
    );
    Ok(signal)
}
