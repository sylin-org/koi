//! Manifest-driven OpenAPI spec builder.
//!
//! Reads the command manifest at startup and builds the full `/openapi.json`
//! spec dynamically.  No `#[utoipa::path]` annotations required on handlers —
//! the [`ApiEndpoint`] entries in `surface.rs` are the single source of truth
//! for path, method, request/response schemas, query params, and content type.

use std::collections::HashSet;

use command_surface::ApiEndpoint;
use utoipa::openapi::{
    path::{HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn},
    request_body::RequestBodyBuilder,
    Content, InfoBuilder, LicenseBuilder, ObjectBuilder, OpenApi, PathItem, PathsBuilder, Ref,
    Required, Response, ResponseBuilder, Type,
};

use crate::surface::MANIFEST;

/// Build the OpenAPI spec driven entirely by the command manifest.
///
/// `schema_docs` must contain *only* component schemas (from per-crate
/// `ApiDoc` structs).  Paths are generated here; schemas come from the
/// `#[derive(ToSchema)]` annotations that remain on the domain types.
pub fn build_openapi(schema_docs: OpenApi) -> OpenApi {
    let mut paths = PathsBuilder::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();

    for def in MANIFEST.all_sorted() {
        for ep in def.api {
            // Deduplicate — the same endpoint may appear in several CommandDefs
            // (e.g. "version" and "status" both map to GET /v1/status).
            if !seen.insert((ep.method, ep.path)) {
                continue;
            }
            let method = parse_method(ep.method);
            let operation = build_operation(ep);
            paths = paths.path(ep.path, PathItem::new(method, operation));
        }
    }

    // System-only endpoints with no CLI equivalent
    paths = add_system_endpoints(paths);

    let info = InfoBuilder::new()
        .title("Koi Network Toolkit API")
        .version(env!("CARGO_PKG_VERSION"))
        .description(Some(
            "Local network toolkit: service discovery, DNS, health monitoring, \
             TLS proxy, and certificate mesh.",
        ))
        .license(Some(
            LicenseBuilder::new().name("Apache-2.0 OR MIT").build(),
        ))
        .build();

    let mut openapi = OpenApi::new(info, paths);
    openapi.merge(schema_docs);
    openapi
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Map a method string (`"GET"`, `"POST"`, …) to the utoipa enum.
fn parse_method(method: &str) -> HttpMethod {
    match method {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => HttpMethod::Get,
    }
}

/// Build an [`Operation`] from one [`ApiEndpoint`].
///
/// Automatically extracts path parameters from `{param}` segments in the
/// path, adds query parameters, sets the request/response bodies, and
/// populates the tag + summary.
fn build_operation(ep: &ApiEndpoint) -> utoipa::openapi::path::Operation {
    let content_type = ep.content_type.unwrap_or("application/json");

    let mut op = OperationBuilder::new().summary(Some(ep.summary));

    // Path parameters from `{param}` segments
    for segment in ep.path.split('/') {
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            op = op.parameter(
                ParameterBuilder::new()
                    .name(name)
                    .parameter_in(ParameterIn::Path)
                    .required(Required::True)
                    .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                    .build(),
            );
        }
    }

    // Query parameters
    for qp in ep.query_params {
        let schema_type = match qp.param_type {
            "integer" => Type::Integer,
            "boolean" => Type::Boolean,
            _ => Type::String,
        };
        let required = if qp.required {
            Required::True
        } else {
            Required::False
        };
        op = op.parameter(
            ParameterBuilder::new()
                .name(qp.name)
                .parameter_in(ParameterIn::Query)
                .required(required)
                .description(Some(qp.description))
                .schema(Some(ObjectBuilder::new().schema_type(schema_type)))
                .build(),
        );
    }

    // Request body
    if let Some(schema_name) = ep.request_body {
        let content = Content::new(Some(Ref::from_schema_name(schema_name)));
        let rb = RequestBodyBuilder::new()
            .content("application/json", content)
            .required(Some(Required::True))
            .build();
        op = op.request_body(Some(rb));
    }

    // Response
    if let Some(schema_name) = ep.response_body {
        let content = Content::new(Some(Ref::from_schema_name(schema_name)));
        let response = ResponseBuilder::new()
            .description("Success")
            .content(content_type, content)
            .build();
        op = op.response("200", response);
    } else {
        op = op.response("200", Response::new("Success"));
    }

    let mut operation = op.build();
    operation.tags = Some(vec![ep.tag.to_string()]);
    operation
}

/// Add system-level endpoints that have no CLI command in the manifest
/// (liveness probe, shutdown).
fn add_system_endpoints(mut paths: PathsBuilder) -> PathsBuilder {
    // GET /healthz
    {
        let mut op = OperationBuilder::new()
            .summary(Some("Basic liveness probe"))
            .response("200", Response::new("Daemon is alive"))
            .build();
        op.tags = Some(vec!["system".to_string()]);
        paths = paths.path(
            crate::adapters::http::paths::HEALTHZ,
            PathItem::new(HttpMethod::Get, op),
        );
    }

    // POST /v1/admin/shutdown
    {
        let response = ResponseBuilder::new()
            .description("Shutdown initiated")
            .content(
                "application/json",
                Content::new(Some(Ref::from_schema_name("ShutdownResponse"))),
            )
            .build();
        let mut op = OperationBuilder::new()
            .summary(Some("Request graceful daemon shutdown"))
            .response("200", response)
            .build();
        op.tags = Some(vec!["system".to_string()]);
        paths = paths.path(
            crate::adapters::http::paths::SHUTDOWN,
            PathItem::new(HttpMethod::Post, op),
        );
    }

    paths
}
