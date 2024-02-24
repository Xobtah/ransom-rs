use std::path::PathBuf;

use clap::Parser;

use crate::ransom::prompt;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    pub bot_token: Option<String>,
    #[arg(short, long)]
    pub channel_id: Option<i64>,
    #[command(subcommand)]
    pub subcommand: Option<SubCommand>,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    #[command(name = "encrypt")]
    Encrypt {
        input: PathBuf,
        #[arg(short, long)]
        key: Option<String>,
    },
    #[command(name = "decrypt")]
    Decrypt {
        input: PathBuf,
        #[arg(short, long)]
        key: String,
    },
}

impl SubCommand {
    const ALL: &'static [&'static str] = &["Encrypt", "Decrypt"];

    pub fn fuzzy_select() -> Result<Self, anyhow::Error> {
        let selection =
            dialoguer::FuzzySelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Select a subcommand")
                .default(0)
                .items(Self::ALL)
                .interact_opt()?;
        if let Some(selection) = selection {
            return Ok(match selection {
                0 => Self::Encrypt {
                    input: prompt("Input file")?.into(),
                    key: None,
                },
                1 => Self::Decrypt {
                    input: prompt("Input file")?.into(),
                    key: prompt("Key")?,
                },
                _ => unreachable!(),
            });
        } else {
            return Err(anyhow::anyhow!("No subcommand selected"));
        }
    }
}
