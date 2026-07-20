use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::lab::{curl_json, Lab};
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

fn wait_for_runtime_instance(base: &str, service_name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        if instances.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("name").and_then(Value::as_str) == Some(service_name))
        }) {
            return Ok(());
        }
        last = instances;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime did not observe service {service_name}: {last}")
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
        match curl_json(
            "GET",
            &format!("{base}/v1/mdns/resolve?name={name}"),
            None,
            None,
        ) {
            Ok(value) if value.get("resolved").is_some() => return Ok(()),
            Ok(value) => last = value,
            Err(error) => last = Value::String(format!("{error:#}")),
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
