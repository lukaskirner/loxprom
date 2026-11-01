//! Loxone WebSocket wire format: message headers, event tables and the
//! header/payload reassembly state machine. Everything here is pure (no I/O).

use anyhow::{Result, bail};

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    BinaryFile,
    ValueStates,
    TextStates,
    DaytimerStates,
    OutOfService,
    Keepalive,
    Weather,
    Unknown(u8),
}

impl Kind {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Kind::Text,
            1 => Kind::BinaryFile,
            2 => Kind::ValueStates,
            3 => Kind::TextStates,
            4 => Kind::DaytimerStates,
            5 => Kind::OutOfService,
            6 => Kind::Keepalive,
            7 => Kind::Weather,
            other => Kind::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    /// An "estimated" header is followed by another header carrying the exact length.
    pub estimated: bool,
    pub len: u32,
}

/// Parse an 8-byte message header. Returns `None` if `b` is not a header.
pub fn parse_header(b: &[u8]) -> Option<Header> {
    if b.len() != HEADER_LEN || b[0] != 0x03 {
        return None;
    }
    Some(Header {
        kind: Kind::from_byte(b[1]),
        estimated: b[2] & 0x01 != 0,
        len: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    })
}

/// Format a 16-byte Loxone UUID as `xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxx`
/// (the representation used in `LoxAPP3.json`).
pub fn format_uuid(b: &[u8]) -> String {
    debug_assert!(b.len() >= 16);
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{}", hex::encode(&b[8..16]))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValueEvent {
    pub uuid: String,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEvent {
    pub uuid: String,
    pub text: String,
}

/// Value event table: repeated `uuid(16) + f64 LE(8)`.
pub fn parse_value_events(b: &[u8]) -> Result<Vec<ValueEvent>> {
    if !b.len().is_multiple_of(24) {
        bail!("value event table length {} is not a multiple of 24", b.len());
    }
    Ok(b.as_chunks::<24>()
        .0
        .iter()
        .map(|c| ValueEvent {
            uuid: format_uuid(&c[..16]),
            value: f64::from_le_bytes(c[16..24].try_into().unwrap()),
        })
        .collect())
}

/// Text event table: repeated `uuid(16) + icon uuid(16) + len u32 LE + text`,
/// each entry padded to a multiple of 4 bytes.
pub fn parse_text_events(b: &[u8]) -> Result<Vec<TextEvent>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < b.len() {
        if b.len() - pos < 36 {
            bail!("truncated text event at offset {pos}");
        }
        let uuid = format_uuid(&b[pos..pos + 16]);
        let len = u32::from_le_bytes(b[pos + 32..pos + 36].try_into().unwrap()) as usize;
        let start = pos + 36;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= b.len())
            .ok_or_else(|| anyhow::anyhow!("text event at offset {pos} overruns the table"))?;
        let text = String::from_utf8_lossy(&b[start..end]).into_owned();
        out.push(TextEvent { uuid, text });
        pos = start + len.div_ceil(4) * 4;
    }
    Ok(out)
}

/// A complete, decoded message from the Miniserver.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// JSON response to a command (`{"LL": ...}`).
    Text(String),
    /// Binary file, e.g. `LoxAPP3.json`.
    File(Vec<u8>),
    Values(Vec<ValueEvent>),
    Texts(Vec<TextEvent>),
    Keepalive,
    OutOfService,
    /// Daytimer, weather or unknown tables: received but not exported.
    Ignored,
}

/// Reassembles the header + payload message pairs of the Loxone protocol.
#[derive(Debug, Default)]
pub struct Framer {
    pending: Option<Header>,
}

impl Framer {
    pub fn push_text(&mut self, text: String) -> Option<Incoming> {
        match self.pending.take() {
            // The Miniserver delivers LoxAPP3.json as a WebSocket *text* message
            // following a binary-file header.
            Some(Header { kind: Kind::BinaryFile, .. }) => Some(Incoming::File(text.into_bytes())),
            _ => Some(Incoming::Text(text)),
        }
    }

    pub fn push_binary(&mut self, data: &[u8]) -> Result<Option<Incoming>> {
        let mut pending = self.pending.take();
        if let Some(stale) = pending
            && data.len() as u64 != u64::from(stale.len)
            && parse_header(data).is_some()
        {
            // A header where a differently-sized payload was expected: the payload we
            // were waiting for never came. Resynchronise on the new header.
            tracing::warn!("dropping header {stale:?}: its payload never arrived");
            pending = None;
        }
        let Some(header) = pending else {
            let Some(h) = parse_header(data) else {
                bail!("expected a message header, got {} bytes", data.len());
            };
            tracing::debug!("header {h:?}");
            if h.estimated {
                // The exact header follows; this one carries no usable length.
                return Ok(None);
            }
            if h.len == 0 {
                return Self::decode(h.kind, &[]);
            }
            self.pending = Some(h);
            return Ok(None);
        };
        Self::decode(header.kind, data)
    }

    fn decode(kind: Kind, payload: &[u8]) -> Result<Option<Incoming>> {
        Ok(Some(match kind {
            Kind::Text => Incoming::Text(String::from_utf8_lossy(payload).into_owned()),
            Kind::BinaryFile => Incoming::File(payload.to_vec()),
            Kind::ValueStates => Incoming::Values(parse_value_events(payload)?),
            Kind::TextStates => Incoming::Texts(parse_text_events(payload)?),
            Kind::Keepalive => Incoming::Keepalive,
            Kind::OutOfService => Incoming::OutOfService,
            Kind::DaytimerStates | Kind::Weather | Kind::Unknown(_) => Incoming::Ignored,
        }))
    }
}

/// Encode helpers, used by the fake Miniserver in tests.
#[cfg(test)]
pub mod encode {
    pub fn header(kind: u8, estimated: bool, len: u32) -> Vec<u8> {
        let mut h = vec![0x03, kind, estimated as u8, 0];
        h.extend_from_slice(&len.to_le_bytes());
        h
    }

    pub fn uuid(s: &str) -> [u8; 16] {
        let p: Vec<&str> = s.split('-').collect();
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&u32::from_str_radix(p[0], 16).unwrap().to_le_bytes());
        out[4..6].copy_from_slice(&u16::from_str_radix(p[1], 16).unwrap().to_le_bytes());
        out[6..8].copy_from_slice(&u16::from_str_radix(p[2], 16).unwrap().to_le_bytes());
        out[8..16].copy_from_slice(&hex::decode(p[3]).unwrap());
        out
    }

    pub fn value_table(entries: &[(&str, f64)]) -> Vec<u8> {
        let mut v = Vec::new();
        for (u, x) in entries {
            v.extend_from_slice(&uuid(u));
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    pub fn text_table(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut v = Vec::new();
        for (u, t) in entries {
            v.extend_from_slice(&uuid(u));
            v.extend_from_slice(&[0u8; 16]);
            v.extend_from_slice(&(t.len() as u32).to_le_bytes());
            v.extend_from_slice(t.as_bytes());
            v.resize(v.len() + (4 - t.len() % 4) % 4, 0);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::encode::*;
    use super::*;

    const U1: &str = "0f869a3f-0155-4b81-ffff403fb0c34b9e";
    const U2: &str = "11111111-2222-3333-4444555566667777";

    #[test]
    fn header_roundtrip() {
        let h = parse_header(&header(2, false, 48)).unwrap();
        assert_eq!(h, Header { kind: Kind::ValueStates, estimated: false, len: 48 });
        assert!(parse_header(&header(0, true, 7)).unwrap().estimated);
        assert!(parse_header(&[0x04, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(parse_header(&[0x03, 0, 0]).is_none());
    }

    #[test]
    fn uuid_format_matches_loxapp3() {
        assert_eq!(format_uuid(&uuid(U1)), U1);
        assert_eq!(format_uuid(&uuid(U2)), U2);
    }

    #[test]
    fn value_table_parses() {
        let t = value_table(&[(U1, 21.5), (U2, -3.0)]);
        let ev = parse_value_events(&t).unwrap();
        assert_eq!(ev, vec![
            ValueEvent { uuid: U1.into(), value: 21.5 },
            ValueEvent { uuid: U2.into(), value: -3.0 },
        ]);
        assert!(parse_value_events(&t[..23]).is_err());
    }

    #[test]
    fn text_table_parses_with_padding() {
        let t = text_table(&[(U1, "Door open"), (U2, "ab"), (U1, "")]);
        let ev = parse_text_events(&t).unwrap();
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].text, "Door open");
        assert_eq!(ev[1], TextEvent { uuid: U2.into(), text: "ab".into() });
        assert_eq!(ev[2].text, "");
        // Corrupt length must not panic.
        let mut bad = text_table(&[(U1, "x")]);
        bad[32] = 0xff;
        assert!(parse_text_events(&bad).is_err());
        assert!(parse_text_events(&bad[..20]).is_err());
    }

    #[test]
    fn framer_pairs_header_and_payload() {
        let mut f = Framer::default();
        let payload = value_table(&[(U1, 1.0)]);
        assert_eq!(f.push_binary(&header(2, false, 24)).unwrap(), None);
        match f.push_binary(&payload).unwrap() {
            Some(Incoming::Values(v)) => assert_eq!(v[0].value, 1.0),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn framer_skips_estimated_header_and_handles_empty_payloads() {
        let mut f = Framer::default();
        assert_eq!(f.push_binary(&header(1, true, 100)).unwrap(), None);
        assert_eq!(f.push_binary(&header(1, false, 3)).unwrap(), None);
        assert_eq!(f.push_binary(b"{}\n").unwrap(), Some(Incoming::File(b"{}\n".to_vec())));
        // Keepalive: header only, no payload message.
        assert_eq!(f.push_binary(&header(6, false, 0)).unwrap(), Some(Incoming::Keepalive));
        assert_eq!(f.push_binary(&header(5, false, 0)).unwrap(), Some(Incoming::OutOfService));
        assert!(f.push_binary(b"garbage").is_err());
    }

    #[test]
    fn framer_resyncs_when_a_payload_never_arrives() {
        let mut f = Framer::default();
        // Header announcing 100 bytes, then (instead of the payload) the next header.
        assert_eq!(f.push_binary(&header(1, false, 100)).unwrap(), None);
        assert_eq!(f.push_binary(&header(1, false, 3)).unwrap(), None);
        assert_eq!(f.push_binary(b"{}\n").unwrap(), Some(Incoming::File(b"{}\n".to_vec())));
        // A payload of exactly the announced size is never mistaken for a header.
        assert_eq!(f.push_binary(&header(1, false, 8)).unwrap(), None);
        let eight = header(2, false, 8);
        assert_eq!(f.push_binary(&eight).unwrap(), Some(Incoming::File(eight)));
    }

    #[test]
    fn framer_file_delivered_as_text_after_two_headers() {
        // Observed on a real Gen 2 Miniserver: two file headers (the first with a
        // different length), then the JSON as a text message.
        let mut f = Framer::default();
        assert_eq!(f.push_binary(&header(1, false, 37765)).unwrap(), None);
        assert_eq!(f.push_binary(&header(1, false, 14553)).unwrap(), None);
        assert_eq!(f.push_text("{\"a\":1}".into()), Some(Incoming::File(b"{\"a\":1}".to_vec())));
        // Plain text responses are unaffected.
        assert_eq!(f.push_binary(&header(0, false, 2)).unwrap(), None);
        assert_eq!(f.push_text("{}".into()), Some(Incoming::Text("{}".into())));
    }

    #[test]
    fn framer_text_responses() {
        let mut f = Framer::default();
        assert_eq!(f.push_binary(&header(0, false, 4)).unwrap(), None);
        assert_eq!(f.push_text("{\"LL\":1}".into()), Some(Incoming::Text("{\"LL\":1}".into())));
        // Ignored table kinds still consume their payload.
        assert_eq!(f.push_binary(&header(7, false, 2)).unwrap(), None);
        assert_eq!(f.push_binary(&[0, 0]).unwrap(), Some(Incoming::Ignored));
    }
}
