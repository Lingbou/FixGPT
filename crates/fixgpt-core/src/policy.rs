use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::token::TurnState;

/// Local account heuristic used to select the expected state shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    Personal,
    Team,
}

impl AccountKind {
    pub fn blocks(&self) -> u8 {
        match self {
            Self::Personal => 10,
            Self::Team => 12,
        }
    }
}

/// Rules used to accept and refresh a turn-state value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatePolicy {
    pub blocks: u8,
    pub ttl_seconds: i64,
    pub refresh_before_seconds: i64,
}

impl StatePolicy {
    pub fn personal() -> Self {
        Self {
            blocks: AccountKind::Personal.blocks(),
            ttl_seconds: 3600,
            refresh_before_seconds: 1200,
        }
    }

    pub fn team() -> Self {
        Self {
            blocks: AccountKind::Team.blocks(),
            ttl_seconds: 3600,
            refresh_before_seconds: 1200,
        }
    }

    pub fn for_account(kind: &AccountKind) -> Self {
        match kind {
            AccountKind::Personal => Self::personal(),
            AccountKind::Team => Self::team(),
        }
    }

    pub fn accept(&self, token: &TurnState, now_seconds: i64) -> bool {
        if token.value.is_empty() || token.blocks != self.blocks as usize {
            return false;
        }
        if token.issued_at > now_seconds.saturating_add(30) {
            return false;
        }
        let expires_at = token
            .issued_at
            .saturating_add(self.ttl_seconds.saturating_sub(30));
        now_seconds < expires_at
    }
}

/// 没有可用 state 时的策略，对应原项目 `state_fallback`。
///
/// - `Strict`：拒绝请求并给出明确原因，不假装采集成功。
/// - `Passthrough`：不注入、正常转发一次，并在响应头标记本次没有注入。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateFallback {
    Strict,
    #[default]
    Passthrough,
}

impl StateFallback {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "passthrough" => Some(Self::Passthrough),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Passthrough => "passthrough",
        }
    }
}

/// 一次生成请求最后是怎么被处理的，用于在页面上给出不含糊的结论。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionMode {
    /// 注入了自己采集的 state。
    Injected,
    /// 没有可用 state，按兜底策略原样转发。
    FallbackPassthrough,
    /// 上游已拒绝该凭据。
    UpstreamRejected,
    /// 没有可用 state 且策略为严格，请求被拒绝。
    Rejected,
}

impl InjectionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Injected => "injected",
            Self::FallbackPassthrough => "fallback-passthrough",
            Self::UpstreamRejected => "upstream-rejected",
            Self::Rejected => "state-unavailable",
        }
    }
}

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_wrong_block_count() {
        let policy = StatePolicy::personal();
        let now = now_seconds();
        let token = TurnState {
            value: "x".into(),
            fingerprint: "f".into(),
            issued_at: now,
            blocks: 11,
        };
        assert!(!policy.accept(&token, now));
    }
}
