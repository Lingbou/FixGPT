use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const HEADER_NAME: &str = "X-Codex-Turn-State";
const MIN_RAW_LEN: usize = 73;
const ENVELOPE_PREFIX: u8 = 0x80;
const FIXED_BYTES: usize = 57;
const BLOCK_BYTES: usize = 16;
const MIN_TIMESTAMP: u64 = 1_577_836_800;
const MAX_TIMESTAMP: u64 = 4_102_444_800;
const MAX_TEXT_LEN: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnState {
    pub value: String,
    pub fingerprint: String,
    pub issued_at: i64,
    pub blocks: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TurnStateError {
    #[error("invalid state encoding")]
    InvalidEncoding,
    #[error("invalid state padding")]
    InvalidPadding,
    #[error("unrecognized state envelope")]
    InvalidEnvelope,
    #[error("state timestamp out of range")]
    InvalidTimestamp,
}

impl TurnState {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, TurnStateError> {
        let value = value.as_ref().trim();
        if value.is_empty()
            || value.len() > MAX_TEXT_LEN
            || value.chars().any(|ch| ch.is_ascii_whitespace())
        {
            return Err(TurnStateError::InvalidEncoding);
        }

        let core = value.trim_end_matches('=');
        if value.len().saturating_sub(core.len()) > 2 {
            return Err(TurnStateError::InvalidPadding);
        }

        let raw = URL_SAFE_NO_PAD
            .decode(core.as_bytes())
            .map_err(|_| TurnStateError::InvalidEncoding)?;

        if raw.len() < MIN_RAW_LEN
            || raw[0] != ENVELOPE_PREFIX
            || raw.len().saturating_sub(FIXED_BYTES) % BLOCK_BYTES != 0
        {
            return Err(TurnStateError::InvalidEnvelope);
        }

        let timestamp = u64::from_be_bytes(
            raw[1..9]
                .try_into()
                .map_err(|_| TurnStateError::InvalidTimestamp)?,
        );
        if !(MIN_TIMESTAMP..MAX_TIMESTAMP).contains(&timestamp) {
            return Err(TurnStateError::InvalidTimestamp);
        }

        let digest = Sha256::digest(value.as_bytes());
        let fingerprint = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        Ok(Self {
            value: value.to_owned(),
            fingerprint,
            issued_at: timestamp as i64,
            blocks: (raw.len() - FIXED_BYTES) / BLOCK_BYTES,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE;

    fn envelope(blocks: usize, timestamp: u64) -> String {
        let mut raw = vec![0_u8; FIXED_BYTES + BLOCK_BYTES * blocks];
        raw[0] = ENVELOPE_PREFIX;
        raw[1..9].copy_from_slice(&timestamp.to_be_bytes());
        URL_SAFE.encode(raw)
    }

    #[test]
    fn parses_padded_and_unpadded_state() {
        let value = envelope(10, 1_800_000_000);
        let parsed = TurnState::parse(&value).expect("padded state");
        assert_eq!(parsed.blocks, 10);
        assert_eq!(parsed.issued_at, 1_800_000_000);

        let unpadded = value.trim_end_matches('=');
        let parsed = TurnState::parse(unpadded).expect("unpadded state");
        assert_eq!(parsed.blocks, 10);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let mut value = envelope(10, 1_800_000_000).into_bytes();
        value[0] = b'A';
        let value = String::from_utf8(value).expect("ascii");
        assert_eq!(
            TurnState::parse(value),
            Err(TurnStateError::InvalidEnvelope)
        );
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert_eq!(
            TurnState::parse("abc def"),
            Err(TurnStateError::InvalidEncoding)
        );
    }

    #[test]
    fn trailing_whitespace_is_trimmed() {
        let value = envelope(10, 1_800_000_000);
        assert!(TurnState::parse(format!("{value}\n")).is_ok());
    }
}
