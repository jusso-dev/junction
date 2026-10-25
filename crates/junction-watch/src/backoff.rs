//! Collector-level retry. Junction's transport retries briefly (ten-second budget);
//! collectors wrap it with longer exponential backoff and full jitter so a
//! throttled tenant is drained gently instead of failing the whole run.
use crate::upstream::CallError;
use std::{future::Future, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            attempts: 5,
            base: Duration::from_secs(2),
            cap: Duration::from_secs(120),
        }
    }
}

impl Backoff {
    /// No waiting; for tests.
    pub const IMMEDIATE: Self = Self {
        attempts: 5,
        base: Duration::ZERO,
        cap: Duration::ZERO,
    };

    /// Delay before retry number `attempt` (0-based). Server `Retry-After` wins,
    /// bounded by `cap`; otherwise full jitter over `base * 2^attempt`.
    pub fn delay(&self, attempt: u32, error: &CallError) -> Duration {
        if let Some(after) = error.retry_after {
            return after.min(self.cap);
        }
        let ceiling = self
            .base
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .min(self.cap);
        let millis = ceiling.as_millis() as u64;
        if millis == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(random_u64() % (millis + 1))
    }

    pub async fn run<T, F, Fut>(&self, mut call: F) -> Result<T, CallError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, CallError>>,
    {
        let mut attempt = 0;
        loop {
            match call().await {
                Ok(value) => return Ok(value),
                // Long server delays belong to the persistent collector schedule;
                // never shorten Retry-After just to fit an in-process retry budget.
                Err(error) if error.retry_after.is_some_and(|d| d > self.cap) => return Err(error),
                Err(error) if error.is_transient() && attempt + 1 < self.attempts => {
                    let delay = self.delay(attempt, &error);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // Jitter only; a failed RNG read falls back to no jitter (zero).
    let _ = getrandom::fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::FailureKind;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn retry_after_is_honoured_and_capped() {
        let b = Backoff::default();
        let mut e = CallError::http(429, None, None);
        e.retry_after = Some(Duration::from_secs(30));
        assert_eq!(b.delay(0, &e), Duration::from_secs(30));
        e.retry_after = Some(Duration::from_secs(9999));
        assert_eq!(b.delay(0, &e), b.cap);
        e.retry_after = None;
        for attempt in 0..10 {
            assert!(b.delay(attempt, &e) <= b.cap);
        }
        assert!(b.delay(0, &e) <= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn retries_transient_then_stops_on_permanent() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, _> = Backoff::IMMEDIATE
            .run(|| async {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(CallError::http(503, None, None))
                } else {
                    Ok(n)
                }
            })
            .await;
        assert_eq!(result.unwrap(), 2);

        let calls = AtomicU32::new(0);
        let result: Result<(), _> = Backoff::IMMEDIATE
            .run(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(CallError::http(403, None, None))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "403 is never retried");

        let calls = AtomicU32::new(0);
        let result: Result<(), _> = Backoff::IMMEDIATE
            .run(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(CallError::other(FailureKind::Transport, "down"))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 5, "bounded attempts");
    }
}
