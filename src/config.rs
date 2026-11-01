use clap::Parser;

/// Prometheus exporter for a Loxone Miniserver (Gen 2), fed by its WebSocket push events.
///
/// The password is read from the LOXONE_PASSWORD environment variable only.
#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct Config {
    /// Miniserver hostname or IP address.
    #[arg(long, env = "LOXONE_HOST")]
    pub host: String,

    /// Miniserver HTTPS/WSS port.
    #[arg(long, env = "LOXONE_PORT", default_value_t = 443)]
    pub port: u16,

    /// Miniserver user (a dedicated read-only user is recommended).
    #[arg(long, env = "LOXONE_USER")]
    pub user: String,

    /// Filled from LOXONE_PASSWORD in `main`; never taken from the command line.
    #[arg(skip)]
    pub password: String,

    /// Address to serve /metrics on.
    #[arg(long, env = "LOXPROM_LISTEN", default_value = "0.0.0.0:9876")]
    pub listen: String,

    /// Name to verify the TLS certificate against instead of --host. Use this when
    /// connecting by IP (e.g. 192-168-1-5.<serial>.dyndns.loxonecloud.com).
    #[arg(long, env = "LOXONE_TLS_SERVER_NAME")]
    pub tls_server_name: Option<String>,

    /// Skip TLS certificate verification entirely (fallback for self-signed certificates).
    #[arg(long, env = "LOXONE_TLS_INSECURE")]
    pub tls_insecure: bool,

    /// How often to check whether the Loxone config changed, in seconds.
    #[arg(long, env = "LOXONE_STRUCTURE_POLL_SECS", default_value_t = 60,
          value_parser = clap::value_parser!(u64).range(1..))]
    pub structure_poll_secs: u64,
}
