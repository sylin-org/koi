//! Authenticated operator HTML on the existing HTTP adapter, never Pond.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use koi_common::mdns_browser::{MdnsQueryOutcome, MdnsQueryRequest, MdnsQueryResult};
use koi_compose::status::{KoiStatus, KoiStatusRuntime};
use koi_dashboard::browser::BrowserState;
use koi_ui::{EndpointActions, Links, OperatorActions, OperatorSnapshot, UiState, View};

pub const SHELL: &str = "/v1/ui/shell";
pub const LOGIN: &str = "/ui";
const TRANSPORT: &str = "/ui/transport.js";
const BROWSER_CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
struct UiRouteState {
    status: Arc<KoiStatusRuntime>,
    preferences_available: bool,
    browser: Option<BrowserState>,
}

/// Mount only when the host configured DAT authentication. An unauthenticated
/// embedded host does not implicitly expose an operator catalog as HTML.
pub(crate) fn routes(
    status: Arc<KoiStatusRuntime>,
    preferences_available: bool,
    browser: Option<BrowserState>,
) -> Router {
    Router::new()
        .route(LOGIN, get(login))
        .route(TRANSPORT, get(transport))
        .route(SHELL, get(snapshot))
        .route("/v1/ui/state", get(operator_state))
        .route(
            "/v1/ui/mdns/query",
            post(mdns_query).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .with_state(UiRouteState {
            status,
            preferences_available,
            browser,
        })
}

async fn login() -> Response {
    let document =
        include_str!("../assets/ui-login.html").replace("{{style}}", &koi_ui::stylesheet());
    response("text/html; charset=utf-8", document, BROWSER_CSP)
}

async fn transport() -> Response {
    let mut source = include_str!("../assets/ui-transport.js").to_owned();
    source.push('\n');
    source.push_str(koi_ui::CARD_EFFECT_SCRIPT);
    source.push('\n');
    source.push_str(koi_ui::INTERACTION_SCRIPT);
    source.push_str(koi_ui::MDNS_INTERACTION_SCRIPT);
    response("text/javascript; charset=utf-8", source, BROWSER_CSP)
}

async fn snapshot(State(route): State<UiRouteState>, request: Request) -> Response {
    let state = match UiState::parse_query(request.uri().query().unwrap_or_default()) {
        Ok(state) => state,
        Err(error) => {
            let mut reply = response(
                "text/plain; charset=utf-8",
                error.into(),
                koi_ui::DOCUMENT_CSP,
            );
            *reply.status_mut() = StatusCode::BAD_REQUEST;
            return reply;
        }
    };
    // Capture once, no join of domain reads, no presentation-owned live state.
    let status = route.status.status();
    let mut operator = operator_snapshot(status.as_ref());
    populate_mdns(&route, &state, &mut operator).await;
    let preference_actions = preference_actions_available(route.preferences_available, &request);
    response(
        "text/html; charset=utf-8",
        koi_ui::render_with_operator_state(
            View::Snapshot(&status.catalog),
            Some(&operator),
            Links {
                refresh: None,
                endpoint_actions: EndpointActions::Browser,
                preference_actions,
                operator_actions: OperatorActions::Browser,
            },
            &state,
        ),
        koi_ui::DOCUMENT_CSP,
    )
}

async fn operator_state(State(route): State<UiRouteState>, request: Request) -> Response {
    let state = match UiState::parse_query(request.uri().query().unwrap_or_default()) {
        Ok(state) => state,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let status = route.status.status();
    let mut operator = operator_snapshot(status.as_ref());
    populate_mdns(&route, &state, &mut operator).await;
    ([("cache-control", "no-store")], axum::Json(operator)).into_response()
}

async fn populate_mdns(route: &UiRouteState, state: &UiState, operator: &mut OperatorSnapshot) {
    if state.destination == koi_ui::Destination::Mdns {
        if let Some(browser) = &route.browser {
            operator.mdns = Some(browser.inspection_snapshot().await);
        }
    }
}

async fn mdns_query(
    State(route): State<UiRouteState>,
    axum::Json(query): axum::Json<MdnsQueryRequest>,
) -> Response {
    if let Err(message) = query.validate() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(query_result(MdnsQueryOutcome::Error, message, vec![])),
        )
            .into_response();
    }
    let Some(browser) = route.browser else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(query_result(
                MdnsQueryOutcome::Error,
                "mDNS browsing is unavailable on this daemon.",
                vec![],
            )),
        )
            .into_response();
    };
    let query_name = match &query {
        MdnsQueryRequest::Requery => koi_common::types::META_QUERY.to_owned(),
        MdnsQueryRequest::Browse { value } | MdnsQueryRequest::Resolve { value } => value.clone(),
    };
    let mut result = execute_mdns_query(&browser, query).await;
    result.query = query_name;
    ([("cache-control", "no-store")], axum::Json(result)).into_response()
}

fn query_result(
    outcome: MdnsQueryOutcome,
    message: impl Into<String>,
    records: Vec<koi_common::types::ServiceRecord>,
) -> MdnsQueryResult {
    MdnsQueryResult {
        outcome,
        message: message.into(),
        records,
        service_types: vec![],
        query: String::new(),
        observed_at: chrono::Utc::now().to_rfc3339(),
    }
}

async fn execute_mdns_query(browser: &BrowserState, query: MdnsQueryRequest) -> MdnsQueryResult {
    use koi_dashboard::browse_source::BrowserEvent;
    use std::time::Duration;
    let query_name = match &query {
        MdnsQueryRequest::Requery => koi_common::types::META_QUERY.to_owned(),
        MdnsQueryRequest::Browse { value } | MdnsQueryRequest::Resolve { value } => value.clone(),
    };
    let mut result = match query {
        MdnsQueryRequest::Requery => {
            browser.meta.requery().await;
            query_result(MdnsQueryOutcome::Started, "Browse-all restart requested. Inspect the source routes and observations below; a started worker is not evidence of an answer.", vec![])
        }
        MdnsQueryRequest::Resolve { value } => {
            match tokio::time::timeout(Duration::from_secs(6), browser.source.resolve(&value)).await {
                Ok(Ok(Some(record))) => query_result(MdnsQueryOutcome::Answers, "The mDNS domain returned an instance record (possibly from its current cache).", vec![record]),
                Ok(Ok(None)) => query_result(MdnsQueryOutcome::NoAnswer, "No resolved instance was returned by the mDNS domain before its timeout.", vec![]),
                Ok(Err(error)) => query_result(MdnsQueryOutcome::Error, error.to_string(), vec![]),
                Err(_) => query_result(MdnsQueryOutcome::NoAnswer, "No resolved instance was returned within six seconds.", vec![]),
            }
        }
        MdnsQueryRequest::Browse { value } => {
            let canonical = if value.eq_ignore_ascii_case(koi_common::types::META_QUERY) {
                koi_common::types::META_QUERY.to_owned()
            } else {
                match koi_common::types::ServiceType::parse_browse(&value) {
                    Ok(value) => value.as_str().to_owned(),
                    Err(_) => {
                        return query_result(
                            MdnsQueryOutcome::Error,
                            "Invalid DNS-SD service type.",
                            vec![],
                        )
                    }
                }
            };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut handle =
                match tokio::time::timeout_at(deadline, browser.source.browse(&canonical)).await {
                    Ok(Ok(handle)) => handle,
                    Ok(Err(error)) => {
                        return query_result(MdnsQueryOutcome::Error, error.to_string(), vec![])
                    }
                    Err(_) => {
                        return query_result(
                            MdnsQueryOutcome::Error,
                            "The provider did not admit the browse within five seconds.",
                            vec![],
                        )
                    }
                };
            let mut records = std::collections::BTreeMap::new();
            let mut stopped_early = false;
            loop {
                match tokio::time::timeout_at(deadline, handle.recv()).await {
                    Ok(Some(BrowserEvent::Found(record) | BrowserEvent::Resolved(record))) => {
                        // Events can include initial replay: report observations, never
                        // imply each came from a new network packet.
                        records.insert(record.name.to_ascii_lowercase(), record);
                        if records.len() >= 256 {
                            stopped_early = true;
                            break;
                        }
                    }
                    Ok(Some(BrowserEvent::Removed { name, .. })) => {
                        records.remove(&name.to_ascii_lowercase());
                    }
                    Ok(Some(BrowserEvent::Resync)) => {
                        records = browser
                            .source
                            .snapshot()
                            .records_for_query(&canonical)
                            .into_iter()
                            .take(256)
                            .map(|record| (record.name.to_ascii_lowercase(), record.clone()))
                            .collect();
                    }
                    Ok(None) => {
                        return query_result(
                            MdnsQueryOutcome::Error,
                            "The provider closed the browse before its observation window ended.",
                            records.into_values().collect(),
                        )
                    }
                    Err(_) => break,
                }
            }
            // Keep ownership until all source checks have completed; dropping the
            // handle releases this request's demand, including on cancellation.
            let snapshot = browser.source.snapshot();
            let available = snapshot
                .sources
                .iter()
                .any(|source| source.query == canonical && source.available);
            if !available {
                return query_result(MdnsQueryOutcome::Error, "No available provider route for this browse. Returned records, if any, may be stale.", records.into_values().collect());
            }
            // A route may change generation while this request observes events.
            // Reconcile from provider-scoped domain truth before claiming answers;
            // best-effort events cannot resurrect observations from a retired route.
            if !snapshot.sources.is_empty() {
                records = snapshot
                    .observations
                    .iter()
                    .filter_map(|observation| {
                        if observation.source.query != canonical || !observation.source.available {
                            return None;
                        }
                        match &observation.value {
                            koi_common::integration::MdnsDiscoveryValue::ServiceRecord {
                                record,
                            }
                            | koi_common::integration::MdnsDiscoveryValue::UnresolvedInstance {
                                record,
                            } => Some((record.name.to_ascii_lowercase(), record.clone())),
                            _ => None,
                        }
                    })
                    .take(256)
                    .collect();
            }
            let types = if canonical == koi_common::types::META_QUERY {
                if snapshot.sources.is_empty() {
                    snapshot.service_types.iter().take(256).cloned().collect()
                } else {
                    snapshot
                        .observations
                        .iter()
                        .filter_map(|observation| {
                            if observation.source.query != canonical
                                || !observation.source.available
                            {
                                return None;
                            }
                            match &observation.value {
                                koi_common::integration::MdnsDiscoveryValue::ServiceType {
                                    service_type,
                                } => Some(service_type.clone()),
                                _ => None,
                            }
                        })
                        .take(256)
                        .collect()
                }
            } else {
                vec![]
            };
            let mut result = if records.is_empty() && types.is_empty() {
                let message = if stopped_early {
                    "Browse stopped early at the 256-record limit, but no current observations remained in the authoritative snapshot. The full five-second window was not observed."
                } else {
                    "No current instance observations remained after five seconds. This does not establish why the network is quiet."
                };
                query_result(MdnsQueryOutcome::NoAnswer, message, vec![])
            } else {
                let message = if stopped_early {
                    "Browse stopped early at the 256-record limit. Results may be incomplete and include current cache replay; at most 256 records and 256 types are returned."
                } else {
                    "Observations returned during the five-second browse, limited to the first 256 records and 256 types (including current cache replay)."
                };
                query_result(
                    MdnsQueryOutcome::Answers,
                    message,
                    records.into_values().collect(),
                )
            };
            result.service_types = types;
            result
        }
    };
    result.query = query_name;
    result.observed_at = chrono::Utc::now().to_rfc3339();
    result
}

pub(crate) fn operator_snapshot(status: &KoiStatus) -> OperatorSnapshot {
    OperatorSnapshot {
        revision: status.revision,
        capabilities: status
            .capabilities
            .iter()
            .map(|report| report.status.clone())
            .collect(),
        certmesh: status.domains.certmesh.as_deref().cloned(),
        dns: status.domains.dns.as_deref().cloned(),
        dns_catalog: status.domains.dns_catalog.as_deref().cloned(),
        pond: status.domains.pond.as_deref().cloned(),
        host: None,
        mdns: None,
    }
}

fn preference_actions_available(preferences_available: bool, request: &Request) -> bool {
    preferences_available
        && request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback())
}

fn response(content_type: &'static str, body: String, csp: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            ("content-type", content_type),
            ("cache-control", "no-store"),
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("x-frame-options", "DENY"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        middleware,
    };
    use tower::ServiceExt;

    fn app() -> Router {
        app_with(Arc::new(KoiStatusRuntime::default()))
    }

    fn app_with(status: Arc<KoiStatusRuntime>) -> Router {
        routes(status, true, None).layer(middleware::from_fn(|request, next| {
            crate::http::dat_auth_middleware(request, next, Arc::new("secret-token".into()))
        }))
    }

    struct QuerySource {
        snapshot: Arc<koi_common::integration::MdnsDiscoverySnapshot>,
        tx: tokio::sync::broadcast::Sender<koi_dashboard::browse_source::BrowserEvent>,
        watch: tokio::sync::watch::Sender<Arc<koi_common::integration::MdnsDiscoverySnapshot>>,
        senders: std::sync::Mutex<
            Vec<tokio::sync::mpsc::Sender<koi_dashboard::browse_source::BrowserEvent>>,
        >,
        answer: bool,
        remove: bool,
    }

    impl koi_dashboard::browse_source::BrowseSource for QuerySource {
        fn browse(
            &self,
            _: &str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            koi_dashboard::browse_source::BrowseHandle,
                            koi_dashboard::browse_source::BrowseError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            if self.answer {
                tx.try_send(koi_dashboard::browse_source::BrowserEvent::Found(
                    koi_common::types::ServiceRecord {
                        name: "Printer".into(),
                        service_type: "_ipp._tcp.local.".into(),
                        host: None,
                        ip: None,
                        port: None,
                        txt: std::collections::HashMap::from([(
                            "note".into(),
                            "<script>bad</script>".into(),
                        )]),
                    },
                ))
                .unwrap();
            }
            if self.remove {
                tx.try_send(koi_dashboard::browse_source::BrowserEvent::Removed {
                    name: "printer".into(),
                    service_type: "_ipp._tcp.local.".into(),
                })
                .unwrap();
            }
            self.senders.lock().unwrap().push(tx);
            Box::pin(async move { Ok(koi_dashboard::browse_source::BrowseHandle::new(rx)) })
        }
        fn subscribe(
            &self,
        ) -> tokio::sync::broadcast::Receiver<koi_dashboard::browse_source::BrowserEvent> {
            self.tx.subscribe()
        }
        fn snapshot(&self) -> Arc<koi_common::integration::MdnsDiscoverySnapshot> {
            self.snapshot.clone()
        }
        fn watch_snapshot(
            &self,
        ) -> tokio::sync::watch::Receiver<Arc<koi_common::integration::MdnsDiscoverySnapshot>>
        {
            self.watch.subscribe()
        }
    }

    fn browser_fixture(answer: bool, available: bool) -> (BrowserState, Arc<QuerySource>) {
        browser_fixture_evidence(answer, available, answer, false)
    }

    fn browser_fixture_evidence(
        answer: bool,
        available: bool,
        retained: bool,
        remove: bool,
    ) -> (BrowserState, Arc<QuerySource>) {
        use koi_common::integration::{
            MdnsDiscoveryObservation, MdnsDiscoverySnapshot, MdnsDiscoverySource,
            MdnsDiscoveryValue,
        };
        let snapshot = Arc::new(MdnsDiscoverySnapshot {
            revision: 42,
            observations: if retained {
                vec![MdnsDiscoveryObservation {
                    source: MdnsDiscoverySource {
                        query: "_ipp._tcp.local.".into(),
                        provider: Some("fixture-provider".into()),
                        generation: 7,
                        available,
                    },
                    value: MdnsDiscoveryValue::UnresolvedInstance {
                        record: koi_common::types::ServiceRecord {
                            name: "Printer".into(),
                            service_type: "_ipp._tcp.local.".into(),
                            host: None,
                            ip: None,
                            port: None,
                            txt: Default::default(),
                        },
                    },
                }]
            } else {
                vec![]
            },
            sources: vec![MdnsDiscoverySource {
                query: "_ipp._tcp.local.".into(),
                provider: Some("fixture-provider".into()),
                generation: 7,
                available,
            }],
            ..Default::default()
        });
        let (tx, _) = tokio::sync::broadcast::channel(8);
        let (watch, _) = tokio::sync::watch::channel(snapshot.clone());
        let source = Arc::new(QuerySource {
            snapshot,
            tx,
            watch,
            senders: Default::default(),
            answer,
            remove,
        });
        let cache = koi_dashboard::browser::BrowserCache::from_snapshot(&source.snapshot);
        let cancel = tokio_util::sync::CancellationToken::new();
        let meta = koi_dashboard::meta_browse::LazyMetaBrowse::new(
            source.clone(),
            cache.clone(),
            cancel.clone(),
        );
        (
            BrowserState::new(source.clone(), cache, meta, cancel),
            source,
        )
    }

    fn app_browser(browser: BrowserState) -> Router {
        routes(Arc::new(KoiStatusRuntime::default()), true, Some(browser)).layer(
            middleware::from_fn(|request, next| {
                crate::http::dat_auth_middleware(request, next, Arc::new("secret-token".into()))
            }),
        )
    }

    #[tokio::test]
    async fn only_authenticated_mdns_view_reads_admit_browse_demand() {
        for endpoint in [SHELL, "/v1/ui/state"] {
            let (browser, source) = browser_fixture(false, true);
            let app = app_browser(browser.clone());
            for query in ["", "?tab=mdns", "?services_view=mdns"] {
                let reply = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("{endpoint}{query}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
            }
            assert!(!browser.meta.is_active());
            let reply = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(endpoint)
                        .header("x-koi-token", "secret-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            assert!(!browser.meta.is_active(), "catalog must remain lazy");
            let reply = app
                .oneshot(
                    Request::builder()
                        .uri(format!("{endpoint}?tab=mdns"))
                        .header("x-koi-token", "secret-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            tokio::task::yield_now().await;
            assert!(browser.meta.is_active());
            assert!(!source.senders.lock().unwrap().is_empty());
            let snapshot = browser.inspection_snapshot().await;
            assert_eq!(snapshot.revision, Some(snapshot.discovery.revision));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn query_outcomes_require_observations_and_available_sources_and_release_demand() {
        for (answer, available, outcome) in [
            (false, true, MdnsQueryOutcome::NoAnswer),
            (true, true, MdnsQueryOutcome::Answers),
            (true, false, MdnsQueryOutcome::Error),
        ] {
            let (browser, source) = browser_fixture(answer, available);
            let result = execute_mdns_query(
                &browser,
                MdnsQueryRequest::Browse {
                    value: "_ipp._tcp".into(),
                },
            )
            .await;
            assert_eq!(result.outcome, outcome);
            assert_eq!(result.records.len(), usize::from(answer));
            assert!(source
                .senders
                .lock()
                .unwrap()
                .iter()
                .all(|sender| sender.is_closed()));
            assert!(
                !browser.meta.is_active(),
                "bounded browse must not start global demand"
            );
        }
        let (browser, _) = browser_fixture(false, true);
        assert_eq!(
            execute_mdns_query(
                &browser,
                MdnsQueryRequest::Resolve {
                    value: "Printer._ipp._tcp.local.".into()
                }
            )
            .await
            .outcome,
            MdnsQueryOutcome::Error,
            "unsupported resolve must fail explicitly"
        );
        assert_eq!(
            execute_mdns_query(&browser, MdnsQueryRequest::Requery)
                .await
                .outcome,
            MdnsQueryOutcome::Started
        );
    }

    #[tokio::test(start_paused = true)]
    async fn authoritative_empty_generation_and_case_changed_goodbye_clear_query_records() {
        let (browser, _) = browser_fixture_evidence(true, true, false, false);
        let result = execute_mdns_query(
            &browser,
            MdnsQueryRequest::Browse {
                value: "_ipp._tcp".into(),
            },
        )
        .await;
        assert_eq!(result.outcome, MdnsQueryOutcome::NoAnswer);
        assert!(
            result.records.is_empty(),
            "an available replacement with no observations must clear retired event data"
        );
        let (browser, _) = browser_fixture_evidence(true, false, false, true);
        let result = execute_mdns_query(
            &browser,
            MdnsQueryRequest::Browse {
                value: "_ipp._tcp".into(),
            },
        )
        .await;
        assert_eq!(result.outcome, MdnsQueryOutcome::Error);
        assert!(
            result.records.is_empty(),
            "case-varied goodbye must remove even fallback event records"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reaching_the_result_cap_reports_early_stop_instead_of_a_full_window() {
        let (browser, source) = browser_fixture(true, true);
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            execute_mdns_query(
                &browser,
                MdnsQueryRequest::Browse {
                    value: "_ipp._tcp".into(),
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        let sender = source.senders.lock().unwrap()[0].clone();
        for index in 0..255 {
            sender
                .send(koi_dashboard::browse_source::BrowserEvent::Found(
                    koi_common::types::ServiceRecord {
                        name: format!("Instance-{index}"),
                        service_type: "_ipp._tcp.local.".into(),
                        host: None,
                        ip: None,
                        port: None,
                        txt: Default::default(),
                    },
                ))
                .await
                .unwrap();
        }
        let result = task.await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(result.outcome, MdnsQueryOutcome::Answers);
        assert!(result.message.contains("stopped early"));
        assert!(result.message.contains("256"));
        assert!(result.records.len() <= 256);
    }

    #[tokio::test]
    async fn cancelled_query_releases_its_browse_handle() {
        let (browser, source) = browser_fixture(false, true);
        let task = tokio::spawn(async move {
            execute_mdns_query(
                &browser,
                MdnsQueryRequest::Browse {
                    value: "_ipp._tcp".into(),
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(source.senders.lock().unwrap().len(), 1);
        task.abort();
        let _ = task.await;
        assert!(source.senders.lock().unwrap()[0].is_closed());
    }

    #[tokio::test]
    async fn query_route_rejects_unauthenticated_unknown_and_hostile_input_before_browsing() {
        let (browser, source) = browser_fixture(false, true);
        let app = app_browser(browser);
        for (body, authenticated, expected) in [
            (
                r#"{"kind":"requery"}"#.to_owned(),
                false,
                StatusCode::UNAUTHORIZED,
            ),
            (
                r#"{"kind":"shell","value":"https://attacker.test"}"#.to_owned(),
                true,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"kind":"requery","value":"bad"}"#.to_owned(),
                true,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"kind":"requery","extra":true}"#.to_owned(),
                true,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"kind":"browse","value":"_ipp._tcp","url":"https://attacker.test"}"#.to_owned(),
                true,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!({"kind":"browse","value":"a".repeat(254)}).to_string(),
                true,
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({"kind":"resolve","value":r"Printer\999._ipp._tcp.local."})
                    .to_string(),
                true,
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({"kind":"resolve","value":"bad._ipp._invalid.local."})
                    .to_string(),
                true,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let mut request = Request::builder()
                .uri("/v1/ui/mdns/query")
                .method("POST")
                .header("content-type", "application/json");
            if authenticated {
                request = request.header("x-koi-token", "secret-token");
            }
            assert_eq!(
                app.clone()
                    .oneshot(request.body(Body::from(body)).unwrap())
                    .await
                    .unwrap()
                    .status(),
                expected
            );
        }
        assert!(source.senders.lock().unwrap().is_empty());
    }

    #[test]
    fn preference_actions_require_the_preferences_core_and_a_loopback_peer() {
        let mut loopback = Request::builder().body(Body::empty()).unwrap();
        loopback
            .extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1000".parse::<SocketAddr>().unwrap()));
        assert!(preference_actions_available(true, &loopback));
        assert!(!preference_actions_available(false, &loopback));

        let mut remote = Request::builder().body(Body::empty()).unwrap();
        remote
            .extensions_mut()
            .insert(ConnectInfo("192.0.2.1:1000".parse::<SocketAddr>().unwrap()));
        assert!(!preference_actions_available(true, &remote));

        let unknown_peer = Request::builder().body(Body::empty()).unwrap();
        assert!(!preference_actions_available(true, &unknown_peer));
    }

    #[tokio::test]
    async fn catalog_html_requires_token_for_every_peer_and_method() {
        for peer in ["127.0.0.1:1000", "192.0.2.1:1000", "[::1]:1000"] {
            for method in ["GET", "HEAD"] {
                for token in [None, Some("wrong"), Some("secret-token")] {
                    let mut request = Request::builder().uri(SHELL).method(method);
                    if let Some(token) = token {
                        request = request.header("x-koi-token", token);
                    }
                    let mut request = request.body(Body::empty()).unwrap();
                    request
                        .extensions_mut()
                        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
                    let reply = app().oneshot(request).await.unwrap();
                    assert_eq!(
                        reply.status(),
                        if token == Some("secret-token") {
                            StatusCode::OK
                        } else {
                            StatusCode::UNAUTHORIZED
                        }
                    );
                    let body = String::from_utf8(
                        to_bytes(reply.into_body(), usize::MAX)
                            .await
                            .unwrap()
                            .to_vec(),
                    )
                    .unwrap();
                    if token != Some("secret-token") {
                        assert!(!body.contains("Snapshot revision"));
                    }
                }
            }
        }
        let reply = app()
            .oneshot(Request::builder().uri(SHELL).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authorized_html_matches_shared_renderer_and_is_never_cached() {
        let runtime = Arc::new(KoiStatusRuntime::default());
        let status = runtime.status();
        let operator = operator_snapshot(status.as_ref());
        let expected = koi_ui::render_with_operator_state(
            View::Snapshot(&status.catalog),
            Some(&operator),
            Links {
                refresh: None,
                endpoint_actions: EndpointActions::Browser,
                preference_actions: false,
                operator_actions: OperatorActions::Browser,
            },
            &UiState::default(),
        );
        let reply = app_with(runtime)
            .oneshot(
                Request::builder()
                    .uri(SHELL)
                    .header("x-koi-token", "secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.headers()["cache-control"], "no-store");
        assert_eq!(
            reply.headers()["content-security-policy"],
            koi_ui::DOCUMENT_CSP
        );
        let body = String::from_utf8(
            to_bytes(reply.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body == expected,
            "adapter must render the captured authoritative snapshot"
        );
        assert!(!body.contains("secret-token"));
    }

    #[tokio::test]
    async fn authorized_view_query_uses_the_shared_typed_renderer() {
        let runtime = Arc::new(KoiStatusRuntime::default());
        for query in [
            "tab=services&q=printer&state=attention&sort=host",
            "tab=private-space",
            "tab=settings",
            "tab=about",
        ] {
            let status = runtime.status();
            let operator = operator_snapshot(status.as_ref());
            let expected = koi_ui::render_with_operator_state(
                View::Snapshot(&status.catalog),
                Some(&operator),
                Links {
                    refresh: None,
                    endpoint_actions: EndpointActions::Browser,
                    preference_actions: false,
                    operator_actions: OperatorActions::Browser,
                },
                &UiState::parse_query(query).unwrap(),
            );
            let reply = app_with(Arc::clone(&runtime))
                .oneshot(
                    Request::builder()
                        .uri(format!("{SHELL}?{query}"))
                        .header("x-koi-token", "secret-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            let bytes = to_bytes(reply.into_body(), usize::MAX).await.unwrap();
            assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn browser_transport_includes_the_shared_card_foil_without_a_token() {
        let reply = app()
            .oneshot(
                Request::builder()
                    .uri(TRANSPORT)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(reply.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("window.KoiCardFoil"));
        assert!(body.contains("--holo"));
        assert!(!body.contains("secret-token"));
    }

    #[tokio::test]
    async fn view_queries_never_bypass_auth_and_invalid_queries_fail_closed() {
        for query in [
            "tab=services",
            "tab=unknown",
            "token=secret-token",
            "q=printer&sort=unknown",
        ] {
            for peer in [None, Some("127.0.0.1:1000"), Some("192.0.2.1:1000")] {
                let mut request = Request::builder()
                    .uri(format!("{SHELL}?{query}"))
                    .body(Body::empty())
                    .unwrap();
                if let Some(peer) = peer {
                    request
                        .extensions_mut()
                        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
                }
                assert_eq!(
                    app().oneshot(request).await.unwrap().status(),
                    StatusCode::UNAUTHORIZED,
                );
            }
        }
        for query in [
            "tab=unknown".to_string(),
            "token=secret-token".to_string(),
            "sort=unknown".to_string(),
            format!("q={}", "a".repeat(8192)),
        ] {
            let reply = app()
                .oneshot(
                    Request::builder()
                        .uri(format!("{SHELL}?{query}"))
                        .header("x-koi-token", "secret-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
            assert_eq!(reply.headers()["cache-control"], "no-store");
            let bytes = to_bytes(reply.into_body(), usize::MAX).await.unwrap();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(!body.contains("secret-token"));
            assert!(!body.contains("<main"));
        }
    }

    #[tokio::test]
    async fn bootstrap_is_public_but_contains_no_catalog_or_credentials() {
        let reply = app()
            .oneshot(Request::builder().uri(LOGIN).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(reply.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("type=\"password\""));
        assert!(!body.contains("Snapshot revision"));
        assert!(!body.contains("secret-token"));
        for route in ["/v1/ui", "/ui/unknown", "/v1/ui/shell/unknown"] {
            assert_eq!(
                app()
                    .oneshot(
                        Request::builder()
                            .uri(route)
                            .header("x-koi-token", "secret-token")
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn encoded_and_noncanonical_paths_cannot_bypass_authentication() {
        for path in [
            "/v1/ui/%73hell",
            "/v1/ui/shell/",
            "/v1/ui//shell",
            "/v1/ui/shell?token=secret-token",
        ] {
            let reply = app()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(reply.status(), StatusCode::OK, "unauthenticated {path}");
        }
    }
}
