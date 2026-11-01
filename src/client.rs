//! Miniserver WebSocket client: connect, authenticate, load the structure,
//! subscribe to status updates and feed the [`Store`]. Reconnects forever.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use crate::auth::{self, LlResponse};
use crate::config::Config;
use crate::protocol::{Framer, Incoming};
use crate::store::Store;
use crate::structure;

const STEP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Loxone locks users out after repeated bad logins, so back off hard on auth errors.
const AUTH_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy)]
pub struct Timings {
    pub keepalive: Duration,
    pub poll: Duration,
    pub idle: Duration,
}

impl Timings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            keepalive: Duration::from_secs(30),
            poll: Duration::from_secs(cfg.structure_poll_secs),
            idle: Duration::from_secs(120),
        }
    }
}

#[derive(Debug)]
pub struct AuthError(pub String);

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authentication failed: {}", self.0)
    }
}
impl std::error::Error for AuthError {}

/// Run forever: connect, serve events, reconnect with backoff.
pub async fn run(cfg: Arc<Config>, store: Arc<Store>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut established = false;
        let result = async {
            let ws = timeout(STEP_TIMEOUT, connect(&cfg)).await.context("connect timed out")??;
            session(ws, &cfg, &store, Timings::from_config(&cfg), &mut established).await
        }
        .await;

        store.set_connected(false);
        store.inc_reconnects();
        let err = result.expect_err("session only ends with an error");
        if established {
            backoff = Duration::from_secs(1);
        }
        let wait = if err.downcast_ref::<AuthError>().is_some() {
            store.inc_auth_failures();
            AUTH_BACKOFF
        } else {
            backoff
        };
        warn!("connection ended: {err:#}; retrying in {}s", wait.as_secs());
        tokio::time::sleep(wait).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(cfg: &Config) -> Result<WebSocketStream<Tls>> {
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .with_context(|| format!("TCP connect to {}:{}", cfg.host, cfg.port))?;
    tcp.set_nodelay(true).ok();
    let name = cfg.tls_server_name.clone().unwrap_or_else(|| cfg.host.clone());
    let server_name = ServerName::try_from(name.clone()).with_context(|| format!("invalid TLS server name {name}"))?;
    let tls = TlsConnector::from(Arc::new(tls_config(cfg.tls_insecure)))
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;
    let mut req = format!("wss://{}:{}/ws/rfc6455", cfg.host, cfg.port).into_client_request()?;
    req.headers_mut().insert("Sec-WebSocket-Protocol", "remotecontrol".parse()?);
    let (ws, _) = tokio_tungstenite::client_async(req, tls).await.context("WebSocket handshake")?;
    Ok(ws)
}

fn tls_config(insecure: bool) -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions");
    if insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    } else {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    }
}

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

struct Rx<S> {
    stream: SplitStream<WebSocketStream<S>>,
    framer: Framer,
}

type Tx<S> = SplitSink<WebSocketStream<S>, Message>;

impl<S: AsyncRead + AsyncWrite + Unpin> Rx<S> {
    /// Cancel-safe: all state lives in `self`, the only await is `stream.next()`.
    async fn recv(&mut self) -> Result<Incoming> {
        loop {
            match self.stream.next().await {
                None => bail!("connection closed"),
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(Message::Text(t))) => {
                    if let Some(i) = self.framer.push_text(t.to_string()) {
                        return Ok(i);
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    if let Some(i) = self.framer.push_binary(&b)? {
                        return Ok(i);
                    }
                }
                Some(Ok(Message::Close(_))) => bail!("server closed the connection"),
                Some(Ok(_)) => {}
            }
        }
    }

    /// Wait for the JSON response to the command whose echoed `control` contains `expect`.
    async fn response(&mut self, expect: &str) -> Result<LlResponse> {
        loop {
            if let Incoming::Text(t) = self.recv().await?
                && let Ok(r) = auth::parse_ll(&t)
                && r.control.contains(expect)
            {
                return Ok(r);
            }
        }
    }

    async fn file(&mut self) -> Result<Vec<u8>> {
        loop {
            let msg = self.recv().await?;
            debug!("while waiting for the structure file got: {}", describe(&msg));
            match msg {
                Incoming::File(f) => return Ok(f),
                Incoming::OutOfService => bail!("miniserver reports out-of-service"),
                _ => {}
            }
        }
    }
}

fn describe(m: &Incoming) -> String {
    match m {
        Incoming::Text(t) => format!("text {:?}", t.chars().take(120).collect::<String>()),
        Incoming::File(f) => format!("file of {} bytes", f.len()),
        Incoming::Values(v) => format!("{} value events", v.len()),
        Incoming::Texts(t) => format!("{} text events", t.len()),
        other => format!("{other:?}"),
    }
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(tx: &mut Tx<S>, cmd: &str) -> Result<()> {
    debug!("-> {}", if cmd.starts_with("jdev/sys/getjwt") { "jdev/sys/getjwt/…" } else { cmd });
    tx.send(Message::text(cmd)).await.context("send")
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(rx: &mut Rx<S>, tx: &mut Tx<S>, cfg: &Config) -> Result<()> {
    let user = auth::encode_segment(&cfg.user);
    send(tx, &format!("jdev/sys/getkey2/{user}")).await?;
    let r = rx.response("getkey2").await?;
    if r.code != 200 {
        return Err(AuthError(format!("getkey2 returned code {}", r.code)).into());
    }
    let key2 = auth::parse_key2(&r).context("parsing getkey2 response")?;
    let hash = auth::auth_hash(&cfg.user, &cfg.password, &key2);
    let client_uuid = uuid::Uuid::new_v4();
    // permission 2 = "web" token; the token is only used for this connection.
    send(tx, &format!("jdev/sys/getjwt/{hash}/{user}/2/{client_uuid}/loxprom")).await?;
    let r = rx.response("getjwt").await?;
    if r.code != 200 {
        return Err(AuthError(format!("getjwt returned code {}", r.code)).into());
    }
    Ok(())
}

/// Drive one connection until it fails. Always returns an error.
pub async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    ws: WebSocketStream<S>,
    cfg: &Config,
    store: &Store,
    timings: Timings,
    established: &mut bool,
) -> Result<()> {
    let (mut tx, stream) = ws.split();
    let mut rx = Rx { stream, framer: Framer::default() };

    timeout(STEP_TIMEOUT, authenticate(&mut rx, &mut tx, cfg)).await.context("authentication timed out")??;
    info!("authenticated as {}", cfg.user);

    send(&mut tx, "data/LoxAPP3.json").await?;
    let raw = timeout(STEP_TIMEOUT, rx.file()).await.context("structure download timed out")??;
    let loaded = structure::parse(&raw)?;
    info!("loaded structure: {} states ({} bytes)", loaded.states.len(), raw.len());
    let mut known_version = loaded.version.clone();
    store.set_structure(loaded);

    send(&mut tx, "jdev/sps/enablebinstatusupdate").await?;
    store.set_connected(true);
    *established = true;

    let mut keepalive = interval(timings.keepalive);
    let mut poll = interval(timings.poll);
    keepalive.tick().await;
    poll.tick().await;
    let mut last_rx = Instant::now();

    loop {
        tokio::select! {
            msg = rx.recv() => {
                last_rx = Instant::now();
                match msg? {
                    Incoming::Values(v) => store.apply_values(v),
                    Incoming::Texts(t) => store.apply_texts(t),
                    Incoming::OutOfService => bail!("miniserver reports out-of-service"),
                    Incoming::File(raw) => match structure::parse(&raw) {
                        Ok(s) => {
                            info!("structure reloaded: {} states", s.states.len());
                            known_version = s.version.clone().or(known_version);
                            store.set_structure(s);
                            // Ask for a full value dump so new controls are populated.
                            send(&mut tx, "jdev/sps/enablebinstatusupdate").await?;
                        }
                        Err(e) => warn!("ignoring unparsable structure file: {e:#}"),
                    },
                    Incoming::Text(t) => {
                        let Ok(r) = auth::parse_ll(&t) else { continue };
                        if r.control.contains("LoxAPPversion3") {
                            let Some(v) = r.value.as_str().map(str::to_string) else { continue };
                            if known_version.as_deref() != Some(v.as_str()) {
                                info!("structure changed ({v}); reloading");
                                known_version = Some(v);
                                send(&mut tx, "data/LoxAPP3.json").await?;
                            }
                        }
                    }
                    Incoming::Keepalive | Incoming::Ignored => {}
                }
            }
            _ = keepalive.tick() => {
                if last_rx.elapsed() > timings.idle {
                    bail!("no data from the miniserver for {}s", last_rx.elapsed().as_secs());
                }
                send(&mut tx, "keepalive").await?;
            }
            _ = poll.tick() => send(&mut tx, "jdev/sps/LoxAPPversion3").await?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::encode;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    const A: &str = "aaaaaaaa-0000-0000-0000000000000001";
    const B: &str = "aaaaaaaa-0000-0000-0000000000000002";
    const C: &str = "aaaaaaaa-0000-0000-0000000000000003";
    const KEY: &str = "4142434445464748494a4b4c4d4e4f50";

    fn structure_json(version: &str, control: &str, uuids: &[(&str, &str)]) -> String {
        let states: Vec<String> = uuids.iter().map(|(n, u)| format!("\"{n}\":\"{u}\"")).collect();
        format!(
            r#"{{"lastModified":"{version}","rooms":{{"r":{{"name":"Kitchen"}}}},"cats":{{}},
               "controls":{{"c":{{"name":"{control}","type":"Test","room":"r","states":{{{}}}}}}}}}"#,
            states.join(",")
        )
    }

    async fn reply_text<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, text: String) {
        ws.send(Message::binary(encode::header(0, false, text.len() as u32))).await.unwrap();
        ws.send(Message::text(text)).await.unwrap();
    }

    /// A tiny fake Miniserver speaking just enough of the protocol.
    async fn fake_miniserver(listener: TcpListener, password: &'static str, current: Arc<Mutex<(String, String)>>) {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let k2 = auth::Key2 { key: hex::decode(KEY).unwrap(), salt: "SALT123".into(), alg: auth::HashAlg::Sha256 };
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(cmd) = msg else { continue };
            let cmd = cmd.to_string();
            if cmd.starts_with("jdev/sys/getkey2/") {
                reply_text(&mut ws, format!(
                    r#"{{"LL":{{"control":"dev/sys/getkey2/prom","value":{{"key":"{KEY}","salt":"SALT123","hashAlg":"SHA256"}},"Code":"200"}}}}"#
                )).await;
            } else if let Some(rest) = cmd.strip_prefix("jdev/sys/getjwt/") {
                let ok = rest.split('/').next() == Some(auth::auth_hash("prom", password, &k2).as_str());
                let code = if ok { "200" } else { "401" };
                reply_text(&mut ws, format!(r#"{{"LL":{{"control":"dev/sys/getjwt","value":"{{}}","Code":"{code}"}}}}"#)).await;
            } else if cmd == "data/LoxAPP3.json" {
                let body = current.lock().unwrap().1.clone();
                // As seen on a real Gen 2 Miniserver: two file headers, then the JSON
                // as a text message.
                ws.send(Message::binary(encode::header(1, false, body.len() as u32 + 1000))).await.unwrap();
                ws.send(Message::binary(encode::header(1, false, body.len() as u32))).await.unwrap();
                ws.send(Message::text(body)).await.unwrap();
            } else if cmd == "jdev/sps/enablebinstatusupdate" {
                reply_text(&mut ws, r#"{"LL":{"control":"dev/sps/enablebinstatusupdate","value":"1","Code":"200"}}"#.into()).await;
                let vals = encode::value_table(&[(A, 21.5), (C, 40.0)]);
                ws.send(Message::binary(encode::header(2, false, vals.len() as u32))).await.unwrap();
                ws.send(Message::binary(vals)).await.unwrap();
                let txt = encode::text_table(&[(B, "Door open")]);
                ws.send(Message::binary(encode::header(3, false, txt.len() as u32))).await.unwrap();
                ws.send(Message::binary(txt)).await.unwrap();
            } else if cmd == "jdev/sps/LoxAPPversion3" {
                let v = current.lock().unwrap().0.clone();
                reply_text(&mut ws, format!(r#"{{"LL":{{"control":"dev/sps/LoxAPPversion3","value":"{v}","Code":"200"}}}}"#)).await;
            } else if cmd == "keepalive" {
                ws.send(Message::binary(encode::header(6, false, 0))).await.unwrap();
            }
        }
    }

    fn test_config(port: u16, password: &str) -> Config {
        Config {
            host: "127.0.0.1".into(), port, user: "prom".into(), password: password.into(),
            listen: "127.0.0.1:0".into(), tls_server_name: None, tls_insecure: false, structure_poll_secs: 1,
        }
    }

    async fn connect_plain(port: u16) -> WebSocketStream<TcpStream> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/ws"), tcp).await.unwrap().0
    }

    const FAST: Timings = Timings {
        keepalive: Duration::from_millis(100),
        poll: Duration::from_millis(100),
        idle: Duration::from_secs(5),
    };

    async fn wait_for(store: &Store, needle: &str) -> String {
        for _ in 0..100 {
            let out = store.render();
            if out.contains(needle) {
                return out;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {needle:?}; last output:\n{}", store.render());
    }

    #[tokio::test]
    async fn end_to_end_values_texts_and_structure_reload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let v1 = structure_json("2024-05-02 10:00:00", "Thermo", &[("temp", A), ("door", B)]);
        let current = Arc::new(Mutex::new(("2024-05-02 10:00:00".to_string(), v1)));
        tokio::spawn(fake_miniserver(listener, "secret", current.clone()));

        let store = Arc::new(Store::new());
        let cfg = test_config(port, "secret");
        let ws = connect_plain(port).await;
        let s2 = store.clone();
        let task = tokio::spawn(async move {
            let mut est = false;
            session(ws, &cfg, &s2, FAST, &mut est).await
        });

        let out = wait_for(&store, "text=\"Door open\"").await;
        assert!(out.contains("loxone_connected 1\n"));
        assert!(out.contains(r#"loxone_value_thermo{state="temp",room="Kitchen",category="",type="Test"} 21.5"#));
        assert!(out.contains(r#"loxone_text_thermo_info{state="door",room="Kitchen",category="",type="Test",text="Door open"} 1"#));
        assert!(out.contains("loxone_skipped_events_total 1\n"), "uuid C is not in v1:\n{out}");
        assert!(out.contains("loxone_structure_last_modified_timestamp_seconds 1714644000\n"));

        // The Loxone config changes: the poll notices, reloads, and re-subscribes.
        let v2 = structure_json("2024-05-02 11:00:00", "Humidity", &[("hum", C)]);
        *current.lock().unwrap() = ("2024-05-02 11:00:00".to_string(), v2);
        let out = wait_for(&store, "loxone_value_humidity{").await;
        assert!(out.contains("} 40\n"));
        assert!(!out.contains("loxone_value_thermo"), "old series must be dropped:\n{out}");
        assert!(!out.contains("Door open"));

        task.abort();
    }

    #[tokio::test]
    async fn wrong_password_is_an_auth_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let current = Arc::new(Mutex::new((String::new(), "{}".to_string())));
        tokio::spawn(fake_miniserver(listener, "secret", current));

        let store = Store::new();
        let cfg = test_config(port, "wrong");
        let mut est = false;
        let err = session(connect_plain(port).await, &cfg, &store, FAST, &mut est).await.unwrap_err();
        assert!(err.downcast_ref::<AuthError>().is_some(), "got {err:#}");
        assert!(!est);
        assert!(store.render().contains("loxone_connected 0\n"));
    }

    #[tokio::test]
    async fn dropped_connection_ends_session_but_keeps_values() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let v1 = structure_json("2024-05-02 10:00:00", "Thermo", &[("temp", A), ("door", B)]);
        let current = Arc::new(Mutex::new(("2024-05-02 10:00:00".to_string(), v1)));
        let server = tokio::spawn(fake_miniserver(listener, "secret", current));

        let store = Arc::new(Store::new());
        let cfg = test_config(port, "secret");
        let ws = connect_plain(port).await;
        let s2 = store.clone();
        let task = tokio::spawn(async move {
            let mut est = false;
            session(ws, &cfg, &s2, FAST, &mut est).await
        });
        wait_for(&store, "} 21.5\n").await;
        server.abort();
        let res = timeout(Duration::from_secs(5), task).await.expect("session must end").unwrap();
        assert!(res.is_err());
        store.set_connected(false); // done by `run`
        let out = store.render();
        assert!(out.contains("loxone_connected 0\n") && out.contains("} 21.5\n"));
    }
}
