use std::path::PathBuf;

use frankenstein::{AsyncApi, AsyncTelegramApi, FileUpload, SendDocumentParams, SendMessageParams};
use log::info;
use rdv_error::RendezVousError;

mod rdv_error;

pub enum RendezVous {
    Telegram(String, i64),
    Discord,
    Socket,
    Email,
}

pub enum Data {
    Text(String),
    Document(PathBuf),
}

impl RendezVous {
    pub async fn send(&self, data: &Data) -> Result<(), RendezVousError> {
        let RendezVous::Telegram(token, channel) = self else {
            unimplemented!();
        };
        match data {
            Data::Text(message) => {
                info!("Sending message on Telegram...");
                AsyncApi::new(token)
                    .send_message(
                        &SendMessageParams::builder()
                            .chat_id(*channel)
                            .text(message)
                            .build(),
                    )
                    .await?;
                info!("Message sent");
            }
            Data::Document(path) => {
                if !path.exists() {
                    return Err(RendezVousError::FileNotFound(path.clone()));
                }
                info!("Sending document on Telegram...");
                AsyncApi::new(token)
                    .send_document(
                        &SendDocumentParams::builder()
                            .chat_id(*channel)
                            .document(FileUpload::from(path.clone()))
                            .build(),
                    )
                    .await?;
                info!("Document sent");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOT_TOKEN: &str = include_str!("../../bot_token.id");
    const CHANNEL_ID: i64 = include!("../../channel.id");

    #[tokio::test]
    async fn send_message_test() {
        assert!(RendezVous::Telegram(BOT_TOKEN.to_string(), CHANNEL_ID)
            .send(&Data::Text("Hello world!".to_string()))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn send_document_test() {
        assert!(RendezVous::Telegram(BOT_TOKEN.to_string(), CHANNEL_ID)
            .send(&Data::Document("../bot_token.id".into()))
            .await
            .is_ok());
    }
}
