//! Well-known mDNS / DNS-SD service-type annotations.
//!
//! Turns a raw service type (`_hap._tcp`) into a human label + description
//! ("HomeKit", "HomeKit accessory") for the network browser. This is the
//! zero-engineering legibility win that makes the browser useful to the
//! smart-home (Home Assistant / Matter / HomeKit / ESPHome) communities, who
//! debug mDNS commissioning on every platform — including Windows, which Avahi
//! and Bonjour serve poorly.
//!
//! The table is intentionally a `match` rather than a lazy map: zero runtime
//! cost, zero dependency, and the compiler keeps it total. Keys are the
//! **normalized** type (no trailing dot, no `.local`), matching the form stored
//! in the browser cache. Add entries freely from IANA's DNS-SD registry and
//! community sources.

/// The friendly `(label, description)` for a normalized service type, or `None`
/// when the type is unknown (the browser then shows the raw type as-is).
pub(crate) fn annotate(service_type: &str) -> Option<(&'static str, &'static str)> {
    let pair = match service_type {
        "_http._tcp" => ("HTTP", "Web service"),
        "_https._tcp" => ("HTTPS", "Secure web service"),
        "_ssh._tcp" => ("SSH", "Secure Shell"),
        "_ftp._tcp" => ("FTP", "File Transfer"),
        "_smb._tcp" => ("SMB/Samba", "Windows file sharing"),
        "_afpovertcp._tcp" => ("AFP", "Apple file sharing"),
        "_nfs._tcp" => ("NFS", "Network file system"),
        "_hap._tcp" => ("HomeKit", "HomeKit accessory"),
        "_matterc._udp" => ("Matter", "Matter commissioning"),
        "_matter._tcp" => ("Matter", "Matter operational"),
        "_esphomelib._tcp" => ("ESPHome", "ESPHome device"),
        "_homeassistant._tcp" => ("Home Assistant", "Home Assistant instance"),
        "_googlecast._tcp" => ("Google Cast", "Chromecast / Google Home"),
        "_spotify-connect._tcp" => ("Spotify", "Spotify Connect"),
        "_airplay._tcp" => ("AirPlay", "Apple AirPlay"),
        "_raop._tcp" => ("AirPlay Audio", "AirPlay audio"),
        "_ipp._tcp" => ("Printer (IPP)", "Internet printing"),
        "_ipps._tcp" => ("Printer (IPPS)", "Secure internet printing"),
        "_printer._tcp" => ("Printer", "Generic printer"),
        "_pdl-datastream._tcp" => ("Printer (PDL)", "PDL printer"),
        "_scanner._tcp" => ("Scanner", "Network scanner"),
        "_mqtt._tcp" => ("MQTT", "Message broker"),
        "_mqtts._tcp" => ("MQTT (TLS)", "Secure message broker"),
        "_daap._tcp" => ("DAAP", "iTunes music sharing"),
        "_dpap._tcp" => ("DPAP", "Apple media sharing"),
        "_rtsp._tcp" => ("RTSP", "Media streaming"),
        "_koi._tcp" => ("Koi", "Koi daemon"),
        "_mcp._tcp" => ("MCP", "Model Context Protocol server"),
        "_certmesh._tcp" => ("Certmesh", "Koi certificate mesh CA"),
        "_services._dns-sd._udp" => ("DNS-SD", "Service discovery meta-query"),
        _ => return None,
    };
    Some(pair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotates_known_types() {
        assert_eq!(
            annotate("_hap._tcp"),
            Some(("HomeKit", "HomeKit accessory"))
        );
        assert_eq!(
            annotate("_matterc._udp"),
            Some(("Matter", "Matter commissioning"))
        );
        assert_eq!(
            annotate("_mcp._tcp"),
            Some(("MCP", "Model Context Protocol server"))
        );
    }

    #[test]
    fn unknown_type_is_none() {
        assert_eq!(annotate("_totally-made-up._tcp"), None);
        // Annotation expects the *normalized* form — a trailing-dot/.local variant
        // is the caller's job to strip (browser cache already does).
        assert_eq!(annotate("_hap._tcp.local"), None);
    }
}
