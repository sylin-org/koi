use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response};
use futures_util::TryStreamExt;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Client;
use url::Url;

use crate::ProxyError;

#[derive(Clone)]
pub struct ForwardState {
    pub backend: Url,
    pub client: Client,
}

pub async fn forward_request(
    State(state): State<ForwardState>,
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
) -> Result<Response<Body>, ProxyError> {
    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let url = state
        .backend
        .join(path)
        .map_err(|e| ProxyError::Forward(format!("Backend URL join failed: {e}")))?;

    let mut builder = state.client.request(parts.method, url.as_str());
    builder = copy_headers(builder, &parts.headers);

    builder = builder.header("X-Forwarded-Proto", "https");
    if let Some(addr) = client_addr {
        builder = builder.header("X-Forwarded-For", addr.ip().to_string());
    }

    let stream = TryStreamExt::map_err(body.into_data_stream(), |e| {
        std::io::Error::other(format!("Body stream error: {e}"))
    });
    let body = reqwest::Body::wrap_stream(stream);

    let response = builder
        .body(body)
        .send()
        .await
        .map_err(|e| ProxyError::Forward(format!("Backend request failed: {e}")))?;

    let mut out = Response::builder().status(response.status());
    if let Some(headers) = out.headers_mut() {
        for (name, value) in response.headers().iter() {
            headers.insert(name, value.clone());
        }
    }

    let stream = TryStreamExt::map_err(response.bytes_stream(), |e| {
        std::io::Error::other(format!("Body stream error: {e}"))
    });
    Ok(out.body(Body::from_stream(stream)).unwrap())
}

fn copy_headers(builder: reqwest::RequestBuilder, headers: &HeaderMap) -> reqwest::RequestBuilder {
    let mut out = builder;
    for (name, value) in headers.iter() {
        if name == axum::http::header::HOST {
            continue;
        }
        let Ok(header_name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        out = out.header(header_name, header_value);
    }
    out
}
