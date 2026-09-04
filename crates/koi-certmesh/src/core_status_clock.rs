//! Time-driven maintenance of the Certmesh status projection.
//!
//! Expiry and renewal conditions change even when no command runs. This clock
//! belongs to the domain because only Certmesh knows which instants change its
//! read model; composition merely owns the cancellation lifetime.

use super::*;

const MAX_STATUS_SLEEP: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const MIN_STATUS_SLEEP: std::time::Duration = std::time::Duration::from_millis(50);
const FAILED_OBSERVATION_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

impl CertmeshCore {
    /// Keep time-derived identity status current until daemon cancellation.
    pub async fn run_status_clock(&self, cancel: tokio_util::sync::CancellationToken) {
        let mut status = self.watch_status();
        let mut ca_anchor = self.watch_ca_anchor();
        loop {
            let delay = next_status_refresh_delay(
                &status.borrow_and_update(),
                &ca_anchor.borrow_and_update(),
            );
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = status.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                changed = ca_anchor.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = tokio::time::sleep(delay) => {
                    self.state.refresh_status().await;
                }
            }
        }
    }
}

fn next_status_refresh_delay(
    status: &CertmeshStatus,
    ca_anchor: &CertmeshCaAnchorSnapshot,
) -> std::time::Duration {
    let now = chrono::Utc::now();
    let mut delay = MAX_STATUS_SLEEP;
    if let Some(identity) = status.identity.info.as_ref() {
        for deadline in [
            identity.renewal.next_renewal_at,
            identity.renewal.expires_at,
        ] {
            if deadline <= now {
                continue;
            }
            if let Ok(until) = (deadline - now).to_std() {
                delay = delay.min(until);
            }
        }
    }
    if matches!(&ca_anchor.state, CertmeshCaAnchorState::Unavailable { .. }) {
        delay = delay.min(FAILED_OBSERVATION_RETRY);
    }
    delay.max(MIN_STATUS_SLEEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_targets_the_next_identity_boundary() {
        let now = chrono::Utc::now();
        let status = CertmeshStatus {
            revision: 0,
            role: CertmeshRole::Member,
            posture: Posture::new(true, false),
            identity: CertmeshIdentityStatus {
                condition: IdentityCondition::Healthy,
                info: Some(IdentityInfo {
                    hostname: "node-01".into(),
                    ca_fingerprint: "abcd".into(),
                    renewal: RenewalHealth {
                        expires_at: now + chrono::Duration::minutes(20),
                        next_renewal_at: now + chrono::Duration::minutes(5),
                        expires_in_days: 0,
                        renew_overdue: false,
                        expired: false,
                    },
                }),
                reason: None,
            },
            diagnosis: koi_common::diagnosis::TrustDiagnosis::from_checks(
                Posture::new(true, false),
                Vec::new(),
            ),
            authority: None,
            reload: None,
            renewal: CertmeshRenewalStatus::default(),
        };
        let delay = next_status_refresh_delay(&status, &CertmeshCaAnchorSnapshot::absent(0));
        assert!(delay <= std::time::Duration::from_secs(5 * 60));
        assert!(delay > std::time::Duration::from_secs(4 * 60));
    }

    #[test]
    fn unavailable_anchor_is_reobserved_promptly() {
        let status = CertmeshStatus {
            revision: 0,
            role: CertmeshRole::Authority,
            posture: Posture::OPEN,
            identity: CertmeshIdentityStatus {
                condition: IdentityCondition::Invalid,
                info: None,
                reason: Some("anchor unavailable".into()),
            },
            diagnosis: koi_common::diagnosis::TrustDiagnosis::from_checks(
                Posture::OPEN,
                Vec::new(),
            ),
            authority: None,
            reload: None,
            renewal: CertmeshRenewalStatus::default(),
        };
        let anchor = CertmeshCaAnchorSnapshot {
            revision: 1,
            state: CertmeshCaAnchorState::Unavailable {
                reason: "permission denied".into(),
            },
        };

        assert_eq!(
            next_status_refresh_delay(&status, &anchor),
            FAILED_OBSERVATION_RETRY
        );
    }
}
