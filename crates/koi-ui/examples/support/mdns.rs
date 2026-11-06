//! Invented edge cases for presentation checks only.
use koi_common::{
    integration::{
        MdnsDiscoveryObservation, MdnsDiscoverySnapshot, MdnsDiscoverySource, MdnsDiscoveryValue,
    },
    mdns_browser::{BrowserSnapshot, ServiceInstance, TypeSummary},
    types::ServiceRecord,
};

pub fn fixture() -> BrowserSnapshot {
    let source = MdnsDiscoverySource {
        query: "_ipp._tcp.local.".into(),
        provider: Some("native".into()),
        generation: 4,
        available: true,
    };
    let mut instances = (0..14)
        .map(|index| ServiceInstance {
            instance_name: format!("Studio printer {index:02}._ipp._tcp.local."),
            name: format!("Studio printer {index:02}"),
            service_type: "_ipp._tcp".into(),
            host: Some(format!("printer-{index:02}.local.")),
            ip: Some(format!("192.0.2.{}", index + 1)),
            port: Some(631),
            txt: [
                (
                    "note".into(),
                    "<script>alert('TXT')</script> & \"quotes\"".into(),
                ),
                ("path".into(), "printers/studio".into()),
            ]
            .into(),
            first_seen: "2026-09-13T10:00:00Z".into(),
            last_seen: "2026-09-13T10:02:00Z".into(),
            resolved: true,
            removed_at: None,
        })
        .collect::<Vec<_>>();
    instances[1].host = None;
    instances[1].ip = None;
    instances[1].port = None;
    instances[1].resolved = false;
    instances[1].txt.clear();
    instances[2].removed_at = Some("2026-09-13T10:03:00Z".into());
    let records = instances
        .iter()
        .filter(|item| item.removed_at.is_none() && item.resolved)
        .map(|item| ServiceRecord {
            name: item.instance_name.clone(),
            service_type: item.service_type.clone(),
            host: item.host.clone(),
            ip: item.ip.clone(),
            port: item.port,
            txt: item.txt.clone(),
        })
        .collect::<Vec<_>>();
    let mut observations = records
        .iter()
        .map(|record| MdnsDiscoveryObservation {
            source: source.clone(),
            value: MdnsDiscoveryValue::ServiceRecord {
                record: record.clone(),
            },
        })
        .collect::<Vec<_>>();
    observations.push(MdnsDiscoveryObservation {
        source: source.clone(),
        value: MdnsDiscoveryValue::UnresolvedInstance {
            record: ServiceRecord {
                name: instances[1].instance_name.clone(),
                service_type: "_ipp._tcp".into(),
                host: None,
                ip: None,
                port: None,
                txt: Default::default(),
            },
        },
    });
    let mut alternate = records[0].clone();
    alternate.ip = Some("198.51.100.42".into());
    alternate
        .txt
        .insert("source-note".into(), "Alternate provider TXT".into());
    observations.push(MdnsDiscoveryObservation {
        source: MdnsDiscoverySource {
            provider: Some("alternate-provider".into()),
            ..source.clone()
        },
        value: MdnsDiscoveryValue::ServiceRecord { record: alternate },
    });
    BrowserSnapshot {
        revision: Some(42),
        total_types: 2,
        total_instances: 13,
        browse_active: true,
        service_types: vec![
            TypeSummary {
                service_type: "_ipp._tcp".into(),
                count: 13,
                label: Some("Internet printing".into()),
                ..Default::default()
            },
            TypeSummary {
                service_type: "_empty._udp".into(),
                count: 0,
                ..Default::default()
            },
        ],
        discovery: MdnsDiscoverySnapshot {
            revision: 42,
            service_types: vec!["_ipp._tcp".into(), "_empty._udp".into()],
            records,
            observations,
            sources: vec![
                source,
                MdnsDiscoverySource {
                    query: "_empty._udp.local.".into(),
                    provider: Some("failed-provider".into()),
                    available: false,
                    generation: 9,
                },
            ],
        },
        instances,
        ..Default::default()
    }
}
