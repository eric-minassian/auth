pub mod templates;

use std::collections::HashMap;
use std::sync::Mutex;

use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("email send failed: {0}")]
    Send(String),
}

/// Outbound mail. Enum, not a trait object: `Ses` in prod, `Stdout` for local
/// dev (also retains the last message per recipient for /api/dev/last-otp),
/// `Capture` for integration tests.
pub enum Mailer {
    Ses(SesMailer),
    Stdout(StdoutMailer),
    Capture(tokio::sync::mpsc::UnboundedSender<EmailMessage>),
}

impl Mailer {
    pub async fn send(&self, msg: EmailMessage) -> Result<(), MailError> {
        match self {
            Self::Ses(m) => m.send(msg).await,
            Self::Stdout(m) => {
                m.send(&msg);
                Ok(())
            }
            Self::Capture(tx) => tx
                .send(msg)
                .map_err(|e| MailError::Send(format!("capture channel closed: {e}"))),
        }
    }
}

pub struct SesMailer {
    client: aws_sdk_sesv2::Client,
    from: String,
}

impl SesMailer {
    pub fn new(client: aws_sdk_sesv2::Client, from: String) -> Self {
        Self { client, from }
    }

    async fn send(&self, msg: EmailMessage) -> Result<(), MailError> {
        let content = |s: &str| Content::builder().data(s).charset("UTF-8").build();
        let body = Body::builder()
            .text(content(&msg.text).map_err(|e| MailError::Send(e.to_string()))?)
            .build();
        let message = Message::builder()
            .subject(content(&msg.subject).map_err(|e| MailError::Send(e.to_string()))?)
            .body(body)
            .build();
        self.client
            .send_email()
            .from_email_address(&self.from)
            .destination(Destination::builder().to_addresses(&msg.to).build())
            .content(EmailContent::builder().simple(message).build())
            .send()
            .await
            .map_err(|e| MailError::Send(format!("{e:?}")))?;
        Ok(())
    }
}

#[derive(Default)]
pub struct StdoutMailer {
    last_by_recipient: Mutex<HashMap<String, String>>,
}

impl StdoutMailer {
    fn send(&self, msg: &EmailMessage) {
        println!(
            "=== email to {} ===\n{}\n{}\n===",
            msg.to, msg.subject, msg.text
        );
        if let Ok(mut map) = self.last_by_recipient.lock() {
            map.insert(msg.to.to_lowercase(), msg.text.clone());
        }
    }

    pub fn last_for(&self, email: &str) -> Option<String> {
        self.last_by_recipient
            .lock()
            .ok()
            .and_then(|map| map.get(&email.to_lowercase()).cloned())
    }
}
