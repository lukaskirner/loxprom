//! Loxone token authentication helpers (`getkey2` / `getjwt`). Pure functions.

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key2 {
    pub key: Vec<u8>,
    pub salt: String,
    pub alg: HashAlg,
}

/// A parsed `{"LL": {"control": ..., "value": ..., "Code": ...}}` response.
#[derive(Debug, Clone, PartialEq)]
pub struct LlResponse {
    pub control: String,
    pub code: i64,
    pub value: Value,
}

pub fn parse_ll(text: &str) -> Result<LlResponse> {
    let v: Value = serde_json::from_str(text).context("response is not JSON")?;
    let ll = v.get("LL").or_else(|| v.get("ll")).ok_or_else(|| anyhow!("no LL object"))?;
    let control = ll.get("control").and_then(Value::as_str).unwrap_or_default().to_string();
    let code = match ll.get("Code").or_else(|| ll.get("code")) {
        Some(Value::String(s)) => s.parse().unwrap_or(-1),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(-1),
        _ => -1,
    };
    let value = ll.get("value").cloned().unwrap_or(Value::Null);
    Ok(LlResponse { control, code, value })
}

impl LlResponse {
    /// `value` is sometimes a JSON object and sometimes a string holding JSON.
    pub fn value_object(&self) -> Result<Value> {
        match &self.value {
            Value::String(s) => serde_json::from_str(s).context("value is not JSON"),
            other => Ok(other.clone()),
        }
    }
}

pub fn parse_key2(resp: &LlResponse) -> Result<Key2> {
    let v = resp.value_object()?;
    let key = v.get("key").and_then(Value::as_str).ok_or_else(|| anyhow!("missing key"))?;
    let salt = v.get("salt").and_then(Value::as_str).ok_or_else(|| anyhow!("missing salt"))?;
    let alg = match v.get("hashAlg").and_then(Value::as_str).unwrap_or("SHA1") {
        a if a.eq_ignore_ascii_case("SHA256") => HashAlg::Sha256,
        a if a.eq_ignore_ascii_case("SHA1") => HashAlg::Sha1,
        other => bail!("unsupported hashAlg {other}"),
    };
    Ok(Key2 { key: hex::decode(key).context("key is not hex")?, salt: salt.to_string(), alg })
}

/// `HMAC(key, user ":" UPPERHEX(HASH(password ":" salt)))`, hex-encoded.
pub fn auth_hash(user: &str, password: &str, k: &Key2) -> String {
    let pw_input = format!("{password}:{}", k.salt);
    let msg_prefix = format!("{user}:");
    match k.alg {
        HashAlg::Sha1 => {
            let pw = hex::encode_upper(Sha1::digest(pw_input.as_bytes()));
            let mut mac = Hmac::<Sha1>::new_from_slice(&k.key).expect("hmac accepts any key length");
            mac.update(msg_prefix.as_bytes());
            mac.update(pw.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        HashAlg::Sha256 => {
            let pw = hex::encode_upper(Sha256::digest(pw_input.as_bytes()));
            let mut mac = Hmac::<Sha256>::new_from_slice(&k.key).expect("hmac accepts any key length");
            mac.update(msg_prefix.as_bytes());
            mac.update(pw.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
    }
}

/// Percent-encode a path segment of a Loxone command.
pub fn encode_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ll_with_string_and_number_codes() {
        let r = parse_ll(r#"{"LL":{"control":"dev/sys/getkey2/u","value":{"key":"0a0b","salt":"s","hashAlg":"SHA256"},"Code":"200"}}"#).unwrap();
        assert_eq!(r.code, 200);
        assert!(r.control.contains("getkey2"));
        assert_eq!(parse_ll(r#"{"LL":{"control":"x","value":"v","code":401}}"#).unwrap().code, 401);
        assert!(parse_ll("not json").is_err());
        assert!(parse_ll("{}").is_err());
    }

    #[test]
    fn key2_accepts_embedded_json_string() {
        let r = parse_ll(r#"{"LL":{"control":"c","value":"{\"key\":\"00ff\",\"salt\":\"abc\",\"hashAlg\":\"SHA1\"}","Code":"200"}}"#).unwrap();
        let k = parse_key2(&r).unwrap();
        assert_eq!(k, Key2 { key: vec![0, 255], salt: "abc".into(), alg: HashAlg::Sha1 });
    }

    // Expected values computed independently with openssl:
    //   pw  = upper(hex(sha(password ":" salt)))
    //   out = hex(hmac(key_bytes, user ":" pw))
    #[test]
    fn hash_vectors_match_openssl() {
        let key = hex::decode("4142434445464748494a4b4c4d4e4f50").unwrap();
        let k256 = Key2 { key: key.clone(), salt: "SALT123".into(), alg: HashAlg::Sha256 };
        let k1 = Key2 { key, salt: "SALT123".into(), alg: HashAlg::Sha1 };
        assert_eq!(auth_hash("prom", "secret", &k256), "bdcbec11ca74db12ae1433f4072f3cb94718e130f7a97868f5fd95abcabba9d7");
        assert_eq!(auth_hash("prom", "secret", &k1), "477801eecd4d9247a2cf04df316a6c7f0eb60dae");
    }

    #[test]
    fn segment_encoding() {
        assert_eq!(encode_segment("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_segment("plain-1_2.3"), "plain-1_2.3");
    }
}
