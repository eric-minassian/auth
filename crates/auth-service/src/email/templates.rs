use crate::domain::otp::OtpPurpose;
use crate::email::EmailMessage;

pub fn otp_email(to: &str, purpose: OtpPurpose, code: &str) -> EmailMessage {
    let (subject, intro) = match purpose {
        OtpPurpose::Signup => (
            "Your verification code",
            "Use this code to finish creating your account:",
        ),
        OtpPurpose::Recovery => (
            "Your account recovery code",
            "Use this code to recover access to your account:",
        ),
    };
    EmailMessage {
        to: to.to_string(),
        subject: subject.to_string(),
        text: format!(
            "{intro}\n\n{code}\n\nThis code expires in 10 minutes. If you didn't request it, you can ignore this email."
        ),
    }
}

/// Sent when someone tries to sign up with an email that already has an
/// account (the HTTP response is a uniform 200 either way — anti-enumeration).
pub fn account_exists_email(to: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_string(),
        subject: "You already have an account".to_string(),
        text: "Someone (hopefully you) tried to sign up with this email, but an account already exists.\n\nIf this was you, use \"Recover account\" on the sign-in page to regain access.\n\nIf it wasn't you, no action is needed."
            .to_string(),
    }
}
