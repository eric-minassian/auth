use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtpPurpose {
    Signup,
    Recovery,
}

impl OtpPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::Recovery => "recovery",
        }
    }
}

pub const OTP_TTL_SECS: i64 = 10 * 60;
pub const OTP_MAX_ATTEMPTS: i64 = 5;
