//! Client IP resolution.
//!
//! The client address comes from the request event metadata, which Zentinel
//! fills in from the TCP connection. Forwarding headers (`X-Forwarded-For`,
//! `X-Real-IP`, ...) are set by whoever sends the request, so they are only
//! consulted when the connection comes from a configured trusted proxy, and
//! then the right-most hop that is not itself a trusted proxy is used.

use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Forwarding headers consulted behind a trusted proxy, in order.
pub fn default_forwarding_headers() -> Vec<String> {
    vec!["x-forwarded-for".to_string(), "x-real-ip".to_string()]
}

/// Set of trusted proxy addresses (IPs and CIDR ranges).
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    /// Parse a list of IPs and CIDR ranges.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.trim();
            let net = if let Ok(net) = entry.parse::<IpNet>() {
                net.trunc()
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                IpNet::from(ip.to_canonical())
            } else {
                return Err(format!(
                    "invalid trusted proxy '{}': expected an IP address or CIDR range",
                    entry
                ));
            };
            nets.push(net);
        }
        Ok(Self { nets })
    }

    /// No trusted proxies configured: forwarding headers are never used.
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `ip` is a trusted proxy.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

/// Parse an address as it appears in metadata or a forwarding header:
/// `1.2.3.4`, `1.2.3.4:5678`, `2001:db8::1`, `[2001:db8::1]:443`.
/// IPv4-mapped IPv6 addresses are returned as IPv4.
pub fn parse_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip().to_canonical());
    }
    value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .and_then(|v| v.parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
}

/// All values of a header, matched case-insensitively.
fn header_values<'a>(headers: &'a HashMap<String, Vec<String>>, name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.iter().map(String::as_str))
        .collect()
}

/// Resolve the client IP of a request.
///
/// `peer` is the client address from the event metadata. Returns `None` when
/// it is not a usable address; callers must not treat that as a trusted or
/// allowed client.
///
/// Only when `peer` is a trusted proxy are `forwarding_headers` consulted (the
/// first one present wins). Hops are read right to left, across repeated header
/// lines, and the first hop that is not a trusted proxy is the client. If every
/// hop is trusted, the left-most is used. A hop that does not parse ends the
/// walk at the last address that did, since nothing to its left can be
/// attributed to a trusted proxy.
pub fn resolve_client_ip(
    peer: &str,
    headers: &HashMap<String, Vec<String>>,
    forwarding_headers: &[String],
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    let peer = parse_ip(peer)?;
    if trusted.is_empty() || !trusted.contains(&peer) {
        return Some(peer);
    }

    for name in forwarding_headers {
        let hops: Vec<&str> = header_values(headers, name)
            .into_iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .collect();
        if hops.is_empty() {
            continue;
        }

        let mut client = peer;
        for hop in hops.iter().rev() {
            match parse_ip(hop) {
                Some(ip) => {
                    client = ip;
                    if !trusted.contains(&ip) {
                        return Some(ip);
                    }
                }
                None => return Some(client),
            }
        }
        return Some(client);
    }

    Some(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in pairs {
            map.entry(k.to_string()).or_default().push(v.to_string());
        }
        map
    }

    fn trusted(entries: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn spoofed_forwarding_headers_ignored_without_trusted_proxies() {
        let h = headers(&[("X-Forwarded-For", "10.0.0.1"), ("X-Real-IP", "10.0.0.2")]);
        let got = resolve_client_ip(
            "203.0.113.7",
            &h,
            &default_forwarding_headers(),
            &TrustedProxies::default(),
        );
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn forwarding_headers_ignored_from_untrusted_peer() {
        let h = headers(&[("x-forwarded-for", "10.0.0.1")]);
        let got = resolve_client_ip(
            "203.0.113.7",
            &h,
            &default_forwarding_headers(),
            &trusted(&["192.0.2.0/24"]),
        );
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn right_most_untrusted_hop_behind_trusted_proxy() {
        // The client prepended a fake hop; the trusted proxies appended the rest.
        let h = headers(&[("X-Forwarded-For", "1.1.1.1, 198.51.100.9, 192.0.2.10")]);
        let got = resolve_client_ip(
            "192.0.2.1",
            &h,
            &default_forwarding_headers(),
            &trusted(&["192.0.2.0/24"]),
        );
        assert_eq!(got, ip("198.51.100.9"));
    }

    #[test]
    fn repeated_header_lines_are_one_list() {
        let h = headers(&[
            ("x-forwarded-for", "1.1.1.1"),
            ("x-forwarded-for", "198.51.100.9, 192.0.2.10"),
        ]);
        let got = resolve_client_ip(
            "192.0.2.1",
            &h,
            &default_forwarding_headers(),
            &trusted(&["192.0.2.0/24"]),
        );
        assert_eq!(got, ip("198.51.100.9"));
    }

    #[test]
    fn all_hops_trusted_uses_left_most() {
        let h = headers(&[("x-forwarded-for", "192.0.2.5, 192.0.2.6")]);
        let got = resolve_client_ip(
            "192.0.2.1",
            &h,
            &default_forwarding_headers(),
            &trusted(&["192.0.2.0/24"]),
        );
        assert_eq!(got, ip("192.0.2.5"));
    }

    #[test]
    fn garbage_hop_stops_the_walk() {
        let h = headers(&[("x-forwarded-for", "1.1.1.1, not-an-ip, 192.0.2.10")]);
        let got = resolve_client_ip(
            "192.0.2.1",
            &h,
            &default_forwarding_headers(),
            &trusted(&["192.0.2.0/24"]),
        );
        assert_eq!(got, ip("192.0.2.10"));
    }

    #[test]
    fn x_real_ip_used_behind_trusted_proxy_when_no_xff() {
        let h = headers(&[("X-Real-IP", "198.51.100.9")]);
        let got = resolve_client_ip(
            "10.1.2.3",
            &h,
            &default_forwarding_headers(),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(got, ip("198.51.100.9"));
    }

    #[test]
    fn trusted_peer_without_headers_is_the_client() {
        let got = resolve_client_ip(
            "10.1.2.3",
            &HashMap::new(),
            &default_forwarding_headers(),
            &trusted(&["10.0.0.0/8"]),
        );
        assert_eq!(got, ip("10.1.2.3"));
    }

    #[test]
    fn unusable_peer_is_none() {
        let h = headers(&[("x-forwarded-for", "198.51.100.9")]);
        for peer in ["", "unknown", "not-an-ip"] {
            assert_eq!(
                resolve_client_ip(
                    peer,
                    &h,
                    &default_forwarding_headers(),
                    &trusted(&["0.0.0.0/0"])
                ),
                None
            );
        }
    }

    #[test]
    fn address_forms() {
        assert_eq!(parse_ip("192.0.2.1:8080"), ip("192.0.2.1"));
        assert_eq!(parse_ip("[2001:db8::1]:443"), ip("2001:db8::1"));
        assert_eq!(parse_ip("[2001:db8::1]"), ip("2001:db8::1"));
        assert_eq!(parse_ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_eq!(parse_ip(" 2001:db8::2 "), ip("2001:db8::2"));
        assert_eq!(parse_ip("unknown"), None);
    }

    #[test]
    fn trusted_proxies_parse() {
        let t = trusted(&["10.0.0.0/8", "192.0.2.1", "2001:db8::/32"]);
        assert!(t.contains(&"10.9.9.9".parse().unwrap()));
        assert!(t.contains(&"::ffff:10.9.9.9".parse().unwrap()));
        assert!(t.contains(&"192.0.2.1".parse().unwrap()));
        assert!(!t.contains(&"192.0.2.2".parse().unwrap()));
        assert!(t.contains(&"2001:db8::5".parse().unwrap()));
        assert!(TrustedProxies::parse(&["nope".to_string()]).is_err());
    }
}
