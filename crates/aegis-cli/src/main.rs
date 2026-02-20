use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const DEFAULT_SOCKET: &str = "/var/run/aegis/aegisd.sock";

#[derive(Parser)]
#[command(name = "aegis", about = "AEGIS - Agent Execution, Governance, and Isolation System", version)]
struct Cli {
    #[arg(long, global = true, env = "AEGIS_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register { ads_file: PathBuf },
    Start { name: String },
    Stop { name: String },
    Status { name: Option<String> },
    #[command(name = "check-fs")]
    CheckFs { agent: String, operation: String, path: String },
    Violations { name: String },
    Capabilities { name: String },
    #[command(name = "verify-audit")]
    VerifyAudit { name: String },
    Validate { ads_file: PathBuf },
    Inspect { ads_file: PathBuf },
    Ping,
}

async fn send(socket: &PathBuf, req: serde_json::Value) -> Result<Resp> {
    let stream = UnixStream::connect(socket).await.context(format!("connect to aegisd at {} failed. Is daemon running?", socket.display()))?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(serde_json::to_string(&req)?.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

#[derive(Deserialize)]
struct Resp { success: bool, message: String, #[serde(default)] data: Option<serde_json::Value> }

fn print(r: &Resp) {
    if r.success { println!("\u{2713} {}", r.message); } else { eprintln!("\u{2717} {}", r.message); }
    if let Some(d) = &r.data { if let Ok(p) = serde_json::to_string_pretty(d) { println!("{}", p); } }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate { ads_file } => match aegis_ads::parse_file(&ads_file) {
            Ok(d) => { println!("\u{2713} '{}' valid\n  Agent: {} (trust: {:?}, framework: {:?})\n  FS read: {} write: {} deny: {}\n  Net egress: {} API scopes: {}", ads_file.display(), d.agent.name, d.agent.trust_level, d.agent.framework, d.capabilities.filesystem.read.len(), d.capabilities.filesystem.write.len(), d.capabilities.filesystem.deny.len(), d.capabilities.network.allow_egress.len(), d.capabilities.api.len()); }
            Err(e) => { eprintln!("\u{2717} Validation failed: {}", e); std::process::exit(1); }
        },
        Commands::Inspect { ads_file } => match aegis_ads::parse_file(&ads_file) {
            Ok(d) => print!("{}", aegis_ads::effective_permissions(&d)),
            Err(e) => { eprintln!("\u{2717} Parse failed: {}", e); std::process::exit(1); }
        },
        Commands::Ping => { print(&send(&cli.socket, serde_json::json!({"command":"ping"})).await?); }
        Commands::Register { ads_file } => {
            let p = std::fs::canonicalize(&ads_file).context(format!("not found: {}", ads_file.display()))?;
            print(&send(&cli.socket, serde_json::json!({"command":"register","ads_path":p.display().to_string()})).await?);
        }
        Commands::Start { name } => { print(&send(&cli.socket, serde_json::json!({"command":"start","agent_name":name})).await?); }
        Commands::Stop { name } => { print(&send(&cli.socket, serde_json::json!({"command":"stop","agent_name":name})).await?); }
        Commands::Status { name } => {
            let r = match name { Some(n) => send(&cli.socket, serde_json::json!({"command":"agent_status","agent_name":n})).await?, None => send(&cli.socket, serde_json::json!({"command":"status"})).await? };
            print(&r);
        }
        Commands::CheckFs { agent, operation, path } => { print(&send(&cli.socket, serde_json::json!({"command":"check_fs","agent_name":agent,"operation":operation,"path":path})).await?); }
        Commands::Violations { name } => { print(&send(&cli.socket, serde_json::json!({"command":"violations","agent_name":name})).await?); }
        Commands::Capabilities { name } => { print(&send(&cli.socket, serde_json::json!({"command":"capabilities","agent_name":name})).await?); }
        Commands::VerifyAudit { name } => { print(&send(&cli.socket, serde_json::json!({"command":"verify_audit","agent_name":name})).await?); }
    }
    Ok(())
}
