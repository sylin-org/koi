use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::lab::{curl_json, curl_status, Lab};
use crate::model::NodeSpec;

/// Wait for one runtime-derived container service to converge through every
/// public capability that consumes it. Keeping the evaluation here gives
/// fault scenarios a single, shared definition of "fully reconstructed".
#[allow(clippy::too_many_arguments)]
pub(crate) fn wait_for_derived_service(
    lab: &Lab,
    primary: &NodeSpec,
    observer: &NodeSpec,
    primary_url: &str,
    observer_url: &str,
    service_name: &str,
    dns_name: &str,
    full_service_name: &str,
    health_name: &str,
) -> Result<()> {
    wait_for_runtime_instance(primary_url, service_name)?;
    wait_for_dns(primary_url, dns_name, primary.address())?;
    wait_for_mdns(observer_url, full_service_name)?;
    wait_for_health(primary_url, health_name)?;
    let ports = primary.lab_ports()?;
    wait_for_proxy(
        primary_url,
        service_name,
        ports.proxy,
        &format!("http://{}:{}", primary.address(), ports.container),
    )?;
    let body = lab.remote_line(
        observer,
        &format!(
            "curl --silent --fail --insecure --max-time 4 https://{}:{}/healthz",
            primary.address(),
            ports.proxy
        ),
    )?;
    if body != "OK" {
        bail!("derived proxy returned {body:?}, expected OK");
    }
    Ok(())
}

pub(crate) fn wait_for_derived_service_absence(
    primary_url: &str,
    observer_url: &str,
    service_name: &str,
    dns_name: &str,
    full_service_name: &str,
    health_name: &str,
) -> Result<()> {
    for _ in 0..80 {
        let instances = curl_json(
            "GET",
            &format!("{primary_url}/v1/runtime/instances"),
            None,
            None,
        )?;
        if !instances.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| derived_service_name(item) == Some(service_name))
        }) {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    let instances = curl_json(
        "GET",
        &format!("{primary_url}/v1/runtime/instances"),
        None,
        None,
    )?;
    if instances.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| derived_service_name(item) == Some(service_name))
    }) {
        bail!("runtime retained stopped service {service_name}");
    }

    wait_for_http_absence(&format!(
        "{primary_url}/v1/dns/lookup?name={dns_name}&type=A"
    ))?;
    let mdns_url = format!("{observer_url}/v1/mdns/resolve?name={full_service_name}");
    let mut mdns_status = 0;
    for _ in 0..20 {
        mdns_status = curl_status("GET", &mdns_url, None)?;
        // 503 = ADR-030 coexistence-skipped responder: the surface is
        // absent by the product's own contract.
        if matches!(mdns_status, 404 | 503 | 504) {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    if !matches!(mdns_status, 404 | 503 | 504) {
        bail!("mDNS service {full_service_name} remained visible with HTTP {mdns_status}");
    }

    for _ in 0..80 {
        let health = curl_json(
            "GET",
            &format!("{primary_url}/v1/health/status"),
            None,
            None,
        )?;
        let health_present = health
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services
                    .iter()
                    .any(|service| service.get("name").and_then(Value::as_str) == Some(health_name))
            });
        let proxy = curl_json("GET", &format!("{primary_url}/v1/proxy/status"), None, None)?;
        let proxy_present = proxy
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies
                    .iter()
                    .any(|proxy| proxy.get("name").and_then(Value::as_str) == Some(service_name))
            });
        if !health_present && !proxy_present {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("derived health or proxy state remained for {service_name}")
}

fn wait_for_http_absence(url: &str) -> Result<()> {
    let mut last = 0;
    for _ in 0..80 {
        last = curl_status("GET", url, None)?;
        if last == 404 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("resource {url} remained visible with HTTP {last}")
}

fn wait_for_runtime_instance(base: &str, service_name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        if instances.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| derived_service_name(item) == Some(service_name))
        }) {
            return Ok(());
        }
        last = instances;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime did not observe service {service_name}: {last}")
}

fn derived_service_name(instance: &Value) -> Option<&str> {
    instance.get("metadata")?.get("name")?.as_str()
}

fn wait_for_dns(base: &str, name: &str, expected: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        match curl_json(
            "GET",
            &format!("{base}/v1/dns/lookup?name={name}&type=A"),
            None,
            None,
        ) {
            Ok(value)
                if value
                    .get("ips")
                    .and_then(Value::as_array)
                    .is_some_and(|ips| ips.iter().any(|ip| ip.as_str() == Some(expected))) =>
            {
                return Ok(())
            }
            Ok(value) => last = value,
            Err(error) => last = Value::String(format!("{error:#}")),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("DNS entry {name} did not converge to {expected}: {last}")
}

fn wait_for_mdns(base: &str, name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        // ADR-030 coexistence: a daemon whose responder deliberately skipped
        // (UDP 5353 already held — every standing service on the mesh since
        // the real-install cutover) has no mDNS surface at all; HTTP 503
        // capability_disabled IS the converged state for this capability.
        let status = curl_status("GET", &format!("{base}/v1/mdns/resolve?name={name}"), None)?;
        match status {
            503 => return Ok(()),
            200 => {
                let value = curl_json(
                    "GET",
                    &format!("{base}/v1/mdns/resolve?name={name}"),
                    None,
                    None,
                )?;
                if value.get("resolved").is_some() {
                    return Ok(());
                }
                last = value;
            }
            other => last = Value::String(format!("HTTP {other}")),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("mDNS service {name} did not resolve: {last}")
}

fn wait_for_health(base: &str, name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        let status = curl_json("GET", &format!("{base}/v1/health/status"), None, None)?;
        if status
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services.iter().any(|service| {
                    service.get("name").and_then(Value::as_str) == Some(name)
                        && service.get("status").and_then(Value::as_str) == Some("up")
                })
            })
        {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("health check {name} did not become up: {last}")
}

fn wait_for_proxy(base: &str, name: &str, port: u16, expected_backend: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        let status = curl_json("GET", &format!("{base}/v1/proxy/status"), None, None)?;
        if status
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies.iter().any(|proxy| {
                    proxy.get("name").and_then(Value::as_str) == Some(name)
                        && proxy.get("listen_port").and_then(Value::as_u64) == Some(u64::from(port))
                        && proxy.get("backend").and_then(Value::as_str) == Some(expected_backend)
                        && proxy.get("state").and_then(Value::as_str) == Some("running")
                })
            })
        {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("proxy {name}:{port} did not become live: {last}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::derived_service_name;

    #[test]
    fn runtime_derived_name_is_read_from_metadata() {
        let instance = json!({
            "name": "engine-container-name",
            "metadata": { "name": "koi-service-deadbeef" }
        });
        assert_eq!(
            derived_service_name(&instance),
            Some("koi-service-deadbeef")
        );
    }
}
