use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// Basic / Bearer auth gate in front of a single upstream service.
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    /// Address to listen on.
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Upstream service that receives authorized requests.
    #[arg(long, env = "UPSTREAM_URL")]
    pub upstream: String,

    /// SQLite file holding the credentials.
    #[arg(long, env = "DATABASE_PATH", default_value = "credentials.db")]
    pub database: PathBuf,

    /// Password for the /__admin/ panel.
    #[arg(long, env = "ADMIN_PASSWORD", hide_env_values = true)]
    pub admin_password: String,

    /// JWT signing secret. Random per start when unset.
    #[arg(long, env = "JWT_SECRET", hide_env_values = true)]
    pub jwt_secret: Option<String>,

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
