use crate::{Links, OperatorActions, OperatorSnapshot};
use koi_certmesh::{CertmeshRole, IdentityCondition};
use koi_common::diagnosis::CheckStatus;
use maud::{html, Markup};

pub fn render(operator: Option<&OperatorSnapshot>, links: Links<'_>) -> Markup {
    let Some(snapshot) = operator else {
        return unavailable();
    };
    let Some(status) = snapshot.certmesh.as_ref() else {
        let restricted = links.operator_actions == OperatorActions::None
            && snapshot.capability("certmesh").is_some();
        let detail = if restricted {
            "Certmesh identity details and operations require the operator interface."
        } else {
            snapshot
                .capability("certmesh")
                .map(|capability| capability.summary.as_str())
                .unwrap_or("Certmesh is not available from this Koi installation.")
        };
        return html! {
            section #private-space.secondary-page aria-labelledby="private-space-title" {
                (heading())
                section.empty-state { h2 { @if restricted { "Operator access required" } @else { "Certmesh is unavailable" } } p { (detail) }
                    p.muted { "Services remain usable without Certmesh." } }
            }
        };
    };

    let can_operate = links.operator_actions != OperatorActions::None;
    let native = links.operator_actions == OperatorActions::Native;
    let role = match status.role {
        CertmeshRole::Open => "Open node",
        CertmeshRole::Member => "Member",
        CertmeshRole::Authority => "Authority",
    };
    let identity = match status.identity.condition {
        IdentityCondition::Absent => "No identity",
        IdentityCondition::Healthy => "Healthy",
        IdentityCondition::Expired => "Expired",
        IdentityCondition::Invalid => "Invalid",
        IdentityCondition::Revoked => "Revoked",
    };

    html! {
        section #private-space.secondary-page aria-labelledby="private-space-title" {
            (heading())
            p.operation-status role="status" aria-live="polite" {}
            section.action-strip data-condition=(format!("{:?}", status.identity.condition).to_lowercase()) {
                div {
                    span.eyebrow { "This machine" }
                    h2 { (role) " · " (identity) }
                    p { "Posture: " (status.posture.level().as_wire()) ". Status revision " (status.revision) "." }
                    @if let Some(info) = &status.identity.info {
                        p.settings-fact { (info.hostname) " · expires " (info.renewal.expires_at.format("%Y-%m-%d")) " · " (info.renewal.expires_in_days) " days" }
                    }
                    @if let Some(reason) = &status.identity.reason { p.info-note { (reason) } }
                    @if status.renewal.consecutive_failures > 0 {
                        p.info-note { "Renewal has failed " (status.renewal.consecutive_failures) " consecutive times. " (status.renewal.last_error.as_deref().unwrap_or("No reason was supplied.")) }
                    }
                }
                @if can_operate && status.role != CertmeshRole::Open {
                    button.button type="button" data-operator-action="certmesh_renew_self" { "Renew identity" }
                }
            }

            @match status.role {
                CertmeshRole::Open => (open_actions(can_operate, native)),
                CertmeshRole::Member => (member_view(status)),
                CertmeshRole::Authority => (authority_view(status, can_operate)),
            }

            section.settings-note { h2 { "Diagnosis" }
                p { "Certmesh membership, application access and browser trust are separate facts." } }
            div.diagnostic-list {
                @for check in &status.diagnosis.checks {
                    article.diagnostic-row data-condition=(check_status_key(check.status)) {
                        div { strong { (check.name.replace('_', " ")) } p { (check.detail) }
                            @if let Some(remedy) = &check.remedy { code { (remedy) } } }
                        span.status-badge { (check_status_label(check.status)) }
                    }
                }
            }
        }
    }
}

fn heading() -> Markup {
    html! { div.page-heading { div {
        span.eyebrow { "Identity under your control" }
        h1 #private-space-title data-ui-heading tabindex="-1" { "Certmesh" }
        p { "Membership, renewal and authority operations for the devices you choose." }
    } } }
}

fn unavailable() -> Markup {
    html! {
        section #private-space.secondary-page aria-labelledby="private-space-title" { (heading())
            section.empty-state { h2 { "Certmesh status is unavailable" }
                p { "Koi could not read the operational snapshot. Existing identity material has not been changed." }
                a.button href="?tab=private-space" data-ui-link { "Retry" } } }
    }
}

fn open_actions(can_operate: bool, native: bool) -> Markup {
    html! {
        div.task-grid {
            section.content-card { h2 { "Create a Certmesh" }
                p { "This machine becomes the authority that signs member identities. Keep the passphrase: Koi cannot recover it." }
                @if can_operate {
                    form.operation-form data-operator-action="certmesh_create" {
                        label { "Profile" select name="profile" { option value="just-me" { "Just me" }
                            option value="team" { "Team with approval" } option value="organization" { "Invitation only" } } }
                        label { "Operator name" input name="operator" autocomplete="off"; }
                        label { "CA passphrase" input type="password" name="passphrase" minlength="8" autocomplete="new-password" required; }
                        label { "Repeat passphrase" input type="password" name="confirm" minlength="8" autocomplete="new-password" required; }
                        button.button type="submit" { "Create Certmesh" }
                    }
                }
            }
            section.content-card { h2 { "Join an existing Certmesh" }
                p { "Joining creates the key on this machine, pins the intended authority and installs the signed identity." }
                @if native {
                    form.operation-form data-operator-action="certmesh_join" {
                        label { "Authority endpoint" input name="endpoint" placeholder="http://192.168.1.44:5641" autocomplete="off" required; }
                        label { "Invite code" input name="invite" autocomplete="off"; }
                        label { "Or enrollment code" input name="totp" inputmode="numeric" autocomplete="one-time-code"; }
                        button.button type="submit" { "Join Certmesh" }
                    }
                } @else { p.info-note { "Joining generates and installs a machine key. Open this destination in the Koi desktop app, or use " code { "koi certmesh join" } "." } }
            }
        }
    }
}

fn member_view(status: &koi_certmesh::CertmeshStatus) -> Markup {
    html! {
        section.content-card { h2 { "Member identity" }
            @if let Some(info) = &status.identity.info { dl.detail-facts {
                dt { "Machine" } dd { (info.hostname) } dt { "Authority fingerprint" } dd { code { (info.ca_fingerprint) } }
                dt { "Next renewal" } dd { (info.renewal.next_renewal_at.format("%Y-%m-%d %H:%M UTC")) } }
            } @else { p { "No usable local identity details are available." } }
            p.muted { "Membership is managed by the authority machine. This node cannot mint invitations or revoke other members." }
        }
    }
}

fn authority_view(status: &koi_certmesh::CertmeshStatus, can_operate: bool) -> Markup {
    let Some(authority) = status.authority.as_ref() else {
        return html! { p.info-note { "This node reports the authority role without an authority snapshot. Review the diagnosis below." } };
    };
    html! {
        section.content-card {
            div.section-heading { div { h2 { "Authority" } p { (authority.member_count) " members · enrollment " (if authority.enrollment_open { "open" } else { "closed" }) } }
                @if can_operate { @if authority.locked {
                    form.inline-operation data-operator-action="certmesh_unlock" { label.sr-only for="unlock-passphrase" { "CA passphrase" }
                        input #unlock-passphrase type="password" name="passphrase" placeholder="CA passphrase" autocomplete="current-password" required;
                        button.button type="submit" { "Unlock" } }
                } @else { button.button type="button" data-operator-action=(if authority.enrollment_open { "certmesh_close_enrollment" } else { "certmesh_open_enrollment" }) {
                    (if authority.enrollment_open { "Close enrollment" } else { "Open enrollment" }) } } }
            }
            dl.detail-facts { dt { "State" } dd { (if authority.locked { "Locked" } else { "Unlocked" }) }
                dt { "CA fingerprint" } dd { code { (authority.ca_fingerprint.as_deref().unwrap_or("Unavailable")) } }
                dt { "Approval" } dd { (if authority.requires_approval { "Required" } else { "Not required" }) } }
        }
        @if !authority.locked && can_operate { section.content-card { h2 { "Invite a member" }
            form.operation-form.compact-form data-operator-action="certmesh_invite" {
                label { "Member hostname" input name="hostname" autocomplete="off" required; }
                label { "Expires after minutes" input type="number" name="ttl_mins" min="1" placeholder="1440"; }
                button.button type="submit" { "Mint invitation" } }
            output.operation-result aria-live="polite" {} } }
        section.members-section { div.section-heading { div { h2 { "Members" } p { "Identities signed by this authority." } } }
            @if authority.members.is_empty() { p.muted { "No members have been enrolled." } }
            @for member in &authority.members { article.member-row data-condition=(member.status.to_lowercase()) {
                div.member-name { strong { (member.hostname) } span { (member.role) } }
                div.member-meta { code { (member.cert_fingerprint) } span { "Expires " (member.cert_expires) } }
                span.status-badge { (member.status) }
                @if !authority.locked && can_operate && member.status.eq_ignore_ascii_case("active") {
                    form.inline-operation data-operator-action="certmesh_revoke" data-confirm=(format!("Revoke {}? This member will no longer be trusted.", member.hostname)) {
                        input type="hidden" name="hostname" value=(member.hostname); input type="hidden" name="reason" value="revoked from Koi";
                        button.danger-button type="submit" { "Revoke" } } }
            } }
        }
        @if can_operate { details.danger-zone { summary { "Authority removal" }
            p { "Destroying the authority erases its CA data, certificates and audit log on this machine. Members keep their certificates until expiry." }
            form.operation-form data-operator-action="certmesh_destroy" data-require-value="DESTROY" {
                label { "Type DESTROY to confirm" input name="confirmation" autocomplete="off" required; }
                button.danger-button type="submit" { "Destroy authority" } } } }
    }
}

const fn check_status_key(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "healthy",
        CheckStatus::Warn => "warning",
        CheckStatus::Red => "danger",
        CheckStatus::NotApplicable => "neutral",
    }
}
const fn check_status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "Passing",
        CheckStatus::Warn => "Attention",
        CheckStatus::Red => "Failed",
        CheckStatus::NotApplicable => "Not applicable",
    }
}
