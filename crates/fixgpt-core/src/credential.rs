use serde::{Deserialize, Serialize};

/// 上游对某个凭据给出的拒绝结论。
///
/// 这是「暂停」而不是「换一条路再试」：一个仍然有效的 turn-state 不该让后续请求
/// 绕过上游的认证失败或配额拒绝。对应原项目 `engine.reject`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectedStatus {
    Unauthorized,
    Forbidden,
    RateLimited,
}

impl RejectedStatus {
    pub fn from_http(status: i64) -> Option<Self> {
        match status {
            401 => Some(Self::Unauthorized),
            403 => Some(Self::Forbidden),
            429 => Some(Self::RateLimited),
            _ => None,
        }
    }

    pub fn code(self) -> i64 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::RateLimited => 429,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLimit {
    /// 401 / 403：在重新认证之前不会自行恢复。
    pub blocked: bool,
    /// 最近一次拒绝状态码，供面板与诊断使用。
    pub rejected_status: i64,
    /// 在这个时刻之前不再向上游发起请求。
    pub retry_until: i64,
}

impl CredentialLimit {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次上游拒绝。返回 true 表示这次拒绝改变了暂停状态。
    ///
    /// `retry_after` 为上游给出的等待秒数；它比本地冷却更长时以它为准。
    pub fn reject(
        &mut self,
        status: RejectedStatus,
        retry_after: i64,
        cooldown_seconds: i64,
        now_seconds: i64,
    ) -> bool {
        let cooldown = cooldown_seconds.max(0);
        match status {
            RejectedStatus::Unauthorized | RejectedStatus::Forbidden => {
                let changed = !self.blocked || self.rejected_status != status.code();
                self.blocked = true;
                self.rejected_status = status.code();
                changed
            }
            RejectedStatus::RateLimited => {
                if !self.blocked {
                    self.rejected_status = status.code();
                }
                let delay = retry_after.max(cooldown);
                let until = now_seconds.saturating_add(delay);
                if until > self.retry_until {
                    self.retry_until = until;
                }
                true
            }
        }
    }

    /// 当前是否应当阻止向上游继续请求。
    pub fn rejection(&self, now_seconds: i64) -> Option<(i64, i64)> {
        if self.blocked {
            return Some((self.rejected_status, 0));
        }
        if now_seconds < self.retry_until {
            let remaining = self.retry_until.saturating_sub(now_seconds);
            return Some((429, remaining));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_blocks_until_reauthentication() {
        let mut limit = CredentialLimit::new();
        assert!(limit.reject(RejectedStatus::Unauthorized, 0, 180, 1_000));
        assert_eq!(limit.rejection(1_000), Some((401, 0)));
        // 再久也不会自行恢复
        assert_eq!(limit.rejection(999_999), Some((401, 0)));
    }

    #[test]
    fn forbidden_is_recorded_as_403() {
        let mut limit = CredentialLimit::new();
        limit.reject(RejectedStatus::Forbidden, 0, 180, 1_000);
        assert_eq!(limit.rejection(1_000), Some((403, 0)));
    }

    #[test]
    fn rate_limit_expires_after_cooldown() {
        let mut limit = CredentialLimit::new();
        limit.reject(RejectedStatus::RateLimited, 0, 180, 1_000);
        assert_eq!(limit.rejection(1_100), Some((429, 80)));
        assert_eq!(limit.rejection(1_181), None);
    }

    #[test]
    fn upstream_retry_after_wins_when_longer() {
        let mut limit = CredentialLimit::new();
        limit.reject(RejectedStatus::RateLimited, 600, 180, 1_000);
        assert_eq!(limit.rejection(1_000), Some((429, 600)));
        // 之后到达的更短等待不能缩短已有的暂停
        limit.reject(RejectedStatus::RateLimited, 10, 180, 1_100);
        assert_eq!(limit.rejection(1_100), Some((429, 500)));
    }

    #[test]
    fn blocked_state_ignores_later_rate_limits() {
        let mut limit = CredentialLimit::new();
        limit.reject(RejectedStatus::Unauthorized, 0, 180, 1_000);
        limit.reject(RejectedStatus::RateLimited, 0, 180, 1_000);
        assert_eq!(limit.rejection(1_000), Some((401, 0)));
    }
}
