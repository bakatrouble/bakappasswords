use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{HeaderMap, StatusCode, Uri, header, request::Parts};
use ipnet::IpNet;

/// Marker suffix on an upstream URL that makes the proxy speak HTTP/2
/// prior-knowledge (cleartext h2c) to that upstream.
const H2C_MARKER: &str = "!h2c";

/// How incoming requests are mapped to upstream services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    /// One upstream; every request goes to it regardless of Host.
    Single(Target),
    /// Several upstreams, each bound to an external hostname.
    ByHost(Vec<HostRoute>),
}

/// An upstream base URL and how to speak to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Base URL, e.g. `http://app:80`.
    pub url: String,
    /// Use HTTP/2 prior-knowledge (h2c) instead of HTTP/1.1.
    pub h2c: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    /// Lowercase hostname without port, e.g. `app.example.com`.
    pub host: String,
    pub target: Target,
}

/// One `--upstream` value, parsed on its own.
///
/// Either a plain URL or `external.domain=upstream-url`, optionally followed
/// by `!h2c`. Whether the set of entries is valid as a whole is checked when
/// converting to [`Routing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamEntry {
    Plain(Target),
    Host(HostRoute),
}

impl FromStr for UpstreamEntry {
    type Err = String;

    fn from_str(entry: &str) -> Result<Self, Self::Err> {
        if !is_host_form(entry) {
            return Ok(Self::Plain(parse_target(entry)?));
        }
        let (host, target) = entry.split_once('=').ok_or_else(|| {
            format!("upstream `{entry}` must use the form external.domain=upstream-url")
        })?;
        let host = host.trim().to_ascii_lowercase();
        validate_host(&host)?;
        let target = parse_target(target.trim())?;
        Ok(Self::Host(HostRoute { host, target }))
    }
}

impl TryFrom<Vec<UpstreamEntry>> for Routing {
    type Error = String;

    /// A single plain URL keeps the original behaviour. Several entries, or
    /// any `host=url` entry, require every entry to use the `host=url` form
    /// with unique hostnames.
    fn try_from(entries: Vec<UpstreamEntry>) -> Result<Self, Self::Error> {
        let mut plain = Vec::new();
        let mut hosts = Vec::new();
        for entry in entries {
            match entry {
                UpstreamEntry::Plain(target) => plain.push(target),
                UpstreamEntry::Host(route) => hosts.push(route),
            }
        }

        match (plain.len(), hosts.len()) {
            (0, 0) => Err("no upstream configured".into()),
            (1, 0) => Ok(Routing::Single(plain.remove(0))),
            (_, 0) => Err(
                "multiple upstreams require the form external.domain=upstream-url for every entry"
                    .into(),
            ),
            (0, _) => {
                let mut seen = HashSet::new();
                for route in &hosts {
                    if !seen.insert(route.host.as_str()) {
                        return Err(format!(
                            "hostname `{}` is mapped to more than one upstream",
                            route.host
                        ));
                    }
                }
                Ok(Routing::ByHost(hosts))
            }
            _ => Err("mixing plain URLs with external.domain=upstream-url entries is not allowed".into()),
        }
    }
}

/// Router state for host-based dispatch.
pub struct HostTable {
    /// Proxy router per lowercase hostname.
    pub routes: HashMap<String, Router>,
    /// Peers allowed to set `X-Forwarded-Host` (e.g. Caddy).
    pub trusted_proxies: Vec<IpNet>,
}

/// An entry is in `host=url` form when it does not start with `http://` or
/// `https://`, so a `=` inside a plain URL's query string is not a separator.
fn is_host_form(entry: &str) -> bool {
    !(entry.starts_with("http://") || entry.starts_with("https://")) && entry.contains('=')
}

/// Parses `url` or `url!h2c`.
fn parse_target(value: &str) -> Result<Target, String> {
    let (url, h2c) = match value.strip_suffix(H2C_MARKER) {
        Some(url) => (url, true),
        None => (value, false),
    };
    validate_url(url)?;
    Ok(Target {
        url: url.to_string(),
        h2c,
    })
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("upstream hostname is empty".into());
    }
    if host.contains(['/', ':', '@', ' ', '[', ']']) {
        return Err(format!("invalid upstream hostname `{host}`"));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("upstream `{url}` must start with http:// or https://"));
    }
    Ok(())
}

/// Request hostname, port stripped and lowercase.
///
/// Source order: `X-Forwarded-Host` (only when the TCP peer is a trusted
/// proxy, last hop value), then the `Host` header, then the URI authority
/// (HTTP/2). An untrusted peer's `X-Forwarded-Host` is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHost(pub String);

impl FromRequestParts<Arc<HostTable>> for RequestHost {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        table: &Arc<HostTable>,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        let trusted = peer.is_some_and(|ip| is_trusted(&table.trusted_proxies, ip));

        parse_host(&parts.headers, &parts.uri, trusted)
            .map(RequestHost)
            .ok_or(StatusCode::NOT_FOUND)
    }
}

fn is_trusted(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|net| net.contains(&ip))
}

fn parse_host(headers: &HeaderMap, uri: &Uri, trusted: bool) -> Option<String> {
    let forwarded = trusted
        .then(|| headers.get_all("x-forwarded-host").iter().last())
        .flatten()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);

    let raw = forwarded
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
        .or_else(|| uri.authority().map(|a| a.as_str().to_owned()))?;

    normalize_host(&raw)
}

/// Strips brackets, port and trailing dot; lowercases.
fn normalize_host(raw: &str) -> Option<String> {
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h)?
    } else {
        raw.split_once(':').map_or(raw, |(h, _)| h)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses each value as clap would, then converts the list.
    fn parse(v: &[&str]) -> Result<Routing, String> {
        let entries = v
            .iter()
            .map(|x| x.parse::<UpstreamEntry>())
            .collect::<Result<Vec<_>, _>>()?;
        Routing::try_from(entries)
    }

    fn target(url: &str, h2c: bool) -> Target {
        Target {
            url: url.into(),
            h2c,
        }
    }

    #[test]
    fn single_plain_url() {
        assert_eq!(
            parse(&["http://app:80"]).unwrap(),
            Routing::Single(target("http://app:80", false))
        );
    }

    #[test]
    fn single_plain_h2c_url() {
        assert_eq!(
            parse(&["http://tempo:4317!h2c"]).unwrap(),
            Routing::Single(target("http://tempo:4317", true))
        );
    }

    #[test]
    fn query_string_in_plain_url_is_not_a_host_form() {
        assert_eq!(
            parse(&["http://app:80/x?a=b"]).unwrap(),
            Routing::Single(target("http://app:80/x?a=b", false))
        );
    }

    #[test]
    fn single_host_mapping_is_host_routed() {
        assert_eq!(
            parse(&["App.Example.com=http://app:80"]).unwrap(),
            Routing::ByHost(vec![HostRoute {
                host: "app.example.com".into(),
                target: target("http://app:80", false),
            }])
        );
    }

    #[test]
    fn host_mapping_with_h2c_marker() {
        assert_eq!(
            parse(&["tempo.example.com=http://tempo:4317!h2c"]).unwrap(),
            Routing::ByHost(vec![HostRoute {
                host: "tempo.example.com".into(),
                target: target("http://tempo:4317", true),
            }])
        );
    }

    #[test]
    fn h2c_marker_requires_http_url() {
        assert!(parse(&["tempo.example.com=tempo:4317!h2c"]).is_err());
        assert!(parse(&["tempo:4317!h2c"]).is_err());
    }

    #[test]
    fn multiple_require_host_form() {
        assert!(parse(&["http://a:80", "b.example.com=http://b:80"]).is_err());
        assert!(parse(&["http://a:80", "http://b:80"]).is_err());
    }

    #[test]
    fn duplicate_hosts_rejected() {
        assert!(parse(&["a.example.com=http://a:80", "A.example.com=http://b:80"]).is_err());
    }

    #[test]
    fn bad_url_rejected() {
        assert!(parse(&["a.example.com=app:80"]).is_err());
        assert!(parse(&["app:80"]).is_err());
    }

    #[test]
    fn empty_host_rejected() {
        assert!(parse(&["=http://a:80", "b.example.com=http://b:80"]).is_err());
    }

    #[test]
    fn no_entries_rejected() {
        assert!(Routing::try_from(Vec::new()).is_err());
    }

    fn table(trusted: &[&str]) -> Arc<HostTable> {
        Arc::new(HostTable {
            routes: HashMap::new(),
            trusted_proxies: trusted.iter().map(|n| n.parse().unwrap()).collect(),
        })
    }

    fn parts(uri: &str, peer: Option<&str>, headers: &[(&str, &str)]) -> Parts {
        let mut b = axum::http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        if let Some(ip) = peer {
            let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
            p.extensions.insert(ConnectInfo(addr));
        }
        p
    }

    async fn extract(p: &mut Parts, t: &Arc<HostTable>) -> Result<String, StatusCode> {
        RequestHost::from_request_parts(p, t).await.map(|h| h.0)
    }

    #[tokio::test]
    async fn host_header_strips_port_and_case() {
        let mut p = parts("/", None, &[("host", "App.Example.com:8080")]);
        assert_eq!(extract(&mut p, &table(&[])).await.as_deref(), Ok("app.example.com"));
    }

    #[tokio::test]
    async fn host_falls_back_to_authority() {
        let mut p = parts("https://b.example.com/x", None, &[]);
        assert_eq!(extract(&mut p, &table(&[])).await.as_deref(), Ok("b.example.com"));
    }

    #[tokio::test]
    async fn forwarded_host_ignored_from_untrusted_peer() {
        let mut p = parts(
            "/",
            Some("198.51.100.7"),
            &[("host", "a.example.com"), ("x-forwarded-host", "evil.example.com")],
        );
        assert_eq!(
            extract(&mut p, &table(&["10.0.0.0/8"])).await.as_deref(),
            Ok("a.example.com")
        );
    }

    #[tokio::test]
    async fn forwarded_host_used_from_trusted_peer() {
        let mut p = parts(
            "/",
            Some("10.1.2.3"),
            &[("host", "caddy.internal"), ("x-forwarded-host", "app.example.com")],
        );
        assert_eq!(
            extract(&mut p, &table(&["10.0.0.0/8"])).await.as_deref(),
            Ok("app.example.com")
        );
    }

    #[tokio::test]
    async fn forwarded_host_uses_last_hop_and_port_is_stripped() {
        let mut p = parts(
            "/",
            Some("10.1.2.3"),
            &[("x-forwarded-host", "spoofed.example.com, API.example.com:443")],
        );
        assert_eq!(
            extract(&mut p, &table(&["10.1.2.3/32"])).await.as_deref(),
            Ok("api.example.com")
        );
    }

    #[tokio::test]
    async fn trusted_peer_without_forwarded_host_falls_back_to_host() {
        let mut p = parts("/", Some("10.1.2.3"), &[("host", "app.example.com")]);
        assert_eq!(
            extract(&mut p, &table(&["10.0.0.0/8"])).await.as_deref(),
            Ok("app.example.com")
        );
    }

    #[tokio::test]
    async fn no_trusted_proxies_means_forwarded_host_is_ignored() {
        let mut p = parts(
            "/",
            Some("10.1.2.3"),
            &[("host", "a.example.com"), ("x-forwarded-host", "b.example.com")],
        );
        assert_eq!(extract(&mut p, &table(&[])).await.as_deref(), Ok("a.example.com"));
    }

    #[tokio::test]
    async fn missing_host_is_not_found() {
        let mut p = parts("/", None, &[]);
        assert_eq!(extract(&mut p, &table(&[])).await, Err(StatusCode::NOT_FOUND));
    }
}
