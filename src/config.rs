use std::net::SocketAddr;
use std::path::PathBuf;

use std::net::IpAddr;

use clap::Parser;
use ipnet::IpNet;

use crate::upstream::UpstreamEntry;

/// Accepts an IP address or CIDR range. A bare IP becomes a single-host range.
fn parse_trusted_proxy(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    s.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|e| format!("`{s}` is not an IP address or CIDR range: {e}"))
}

/// Basic / Bearer auth gate in front of one or more upstream services.
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    /// Address to listen on.
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Upstream service(s) that receive authorized requests. Either one plain URL,
    /// or `external.domain=upstream-url` entries matched by the request host.
    /// Repeat the flag to add more entries.
    #[arg(long = "upstream", env = "UPSTREAM_URL", required = true)]
    pub upstream: Vec<UpstreamEntry>,

    /// SQLite file holding the credentials.
    #[arg(long, env = "DATABASE_PATH", default_value = "credentials.db")]
    pub database: PathBuf,

    /// Password for the /__admin/ panel.
    #[arg(long, env = "ADMIN_PASSWORD", hide_env_values = true)]
    pub admin_password: String,

    /// JWT signing secret. Random per start when unset.
    #[arg(long, env = "JWT_SECRET", hide_env_values = true)]
    pub jwt_secret: Option<String>,

    /// Trusted reverse proxies (IPs or CIDRs, e.g. Caddy). Only connections from
    /// these peers may set X-Forwarded-Host. Empty disables the header.
    #[arg(
        long,
        env = "TRUSTED_PROXIES",
        value_delimiter = ',',
        value_parser = parse_trusted_proxy
    )]
    pub trusted_proxies: Vec<IpNet>,

    /// Admin JWT lifetime in hours.
    #[arg(long, env = "JWT_TTL_HOURS", default_value_t = 12)]
    pub jwt_ttl_hours: u64,

    /// Realm advertised in WWW-Authenticate.
    #[arg(long, env = "AUTH_REALM", default_value = "protected")]
    pub realm: String,

    /// Seconds to let in-flight requests finish after SIGINT/SIGTERM before exiting.
    #[arg(long, env = "SHUTDOWN_GRACE_SECS", default_value_t = 3)]
    pub shutdown_grace_secs: u64,
}
