//! Parses `LoxAPP3.json` into a flat map of state UUID -> label metadata.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMeta {
    /// Original control name (used in log messages only).
    pub control: String,
    /// Normalized, de-duplicated control name used inside metric names.
    pub name: String,
    pub state: String,
    pub room: String,
    pub category: String,
    pub ctype: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Structure {
    pub states: HashMap<String, StateMeta>,
    /// The `lastModified` string, e.g. `2024-05-02 10:33:07`. Also what
    /// `jdev/sps/LoxAPPversion3` returns, so it doubles as the change marker.
    pub version: Option<String>,
    /// `version` as epoch seconds (the Miniserver's local time read as UTC).
    pub last_modified_epoch: Option<f64>,
}

pub fn parse(json: &[u8]) -> Result<Structure> {
    let body = json.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(json);
    let root: Value = serde_json::from_slice(body).with_context(|| {
        let n = body.len().min(48);
        format!(
            "LoxAPP3.json is not valid JSON ({} bytes; first bytes: {} / {:?})",
            body.len(),
            hex::encode(&body[..n]),
            String::from_utf8_lossy(&body[..n])
        )
    })?;
    let names = |key: &str| -> HashMap<String, String> {
        root.get(key)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.get("name")?.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };
    tracing::debug!("LoxAPP3.json layout: {}", describe_layout(&root));
    let rooms = names("rooms");
    let cats = names("cats");

    let mut raw = HashMap::new();
    if let Some(controls) = root.get("controls").and_then(Value::as_object) {
        for control in controls.values() {
            collect_control(control, None, &rooms, &cats, &mut raw);
        }
    }
    let states = assign_names(raw);

    let version = root.get("lastModified").and_then(Value::as_str).map(str::to_string);
    let last_modified_epoch = version.as_deref().and_then(parse_timestamp);
    Ok(Structure { states, version, last_modified_epoch })
}

/// Names and sizes only, never values: top-level keys and the shape of the first control.
fn describe_layout(root: &Value) -> String {
    let size = |v: &Value| match v {
        Value::Object(m) => format!("object({})", m.len()),
        Value::Array(a) => format!("array({})", a.len()),
        Value::String(_) => "string".to_string(),
        other => format!("{other}"),
    };
    let top: Vec<String> = root
        .as_object()
        .map(|m| m.iter().map(|(k, v)| format!("{k}={}", size(v))).collect())
        .unwrap_or_default();
    let first = root
        .get("controls")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(Value::as_object)
        .map(|c| c.iter().map(|(k, v)| format!("{k}={}", size(v))).collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "none".into());
    format!("top-level [{}]; first control [{first}]", top.join(", "))
}

fn collect_control(
    control: &Value,
    parent: Option<(&str, &str, &str)>,
    rooms: &HashMap<String, String>,
    cats: &HashMap<String, String>,
    out: &mut HashMap<String, StateMeta>,
) {
    let own_name = control.get("name").and_then(Value::as_str).unwrap_or("");
    let lookup = |field: &str, map: &HashMap<String, String>| {
        control.get(field).and_then(Value::as_str).and_then(|id| map.get(id)).cloned()
    };
    let name = match parent {
        Some((p, _, _)) => format!("{p} / {own_name}"),
        None => own_name.to_string(),
    };
    let room = lookup("room", rooms).or_else(|| parent.map(|p| p.1.to_string())).unwrap_or_default();
    let category = lookup("cat", cats).or_else(|| parent.map(|p| p.2.to_string())).unwrap_or_default();
    let ctype = control.get("type").and_then(Value::as_str).unwrap_or("").to_string();

    if let Some(states) = control.get("states").and_then(Value::as_object) {
        for (state_name, v) in states {
            collect_state(state_name, v, &name, &room, &category, &ctype, out);
        }
    }
    if let Some(subs) = control.get("subControls").and_then(Value::as_object) {
        for sub in subs.values() {
            collect_control(sub, Some((&name, &room, &category)), rooms, cats, out);
        }
    }
}

fn collect_state(
    label: &str,
    v: &Value,
    control: &str,
    room: &str,
    category: &str,
    ctype: &str,
    out: &mut HashMap<String, StateMeta>,
) {
    let mut add = |uuid: &str, state: String| {
        out.insert(
            uuid.to_string(),
            StateMeta {
                control: control.to_string(),
                name: normalize(control),
                state,
                room: room.to_string(),
                category: category.to_string(),
                ctype: ctype.to_string(),
            },
        );
    };
    match v {
        Value::String(u) => add(u, label.to_string()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                if let Some(u) = item.as_str() {
                    let l = if items.len() == 1 { label.to_string() } else { format!("{label}[{i}]") };
                    add(u, l);
                }
            }
        }
        Value::Object(m) => {
            for (k, inner) in m {
                collect_state(&format!("{label}.{k}"), inner, control, room, category, ctype, out);
            }
        }
        _ => {}
    }
}

/// Turn a control name into the lowercase, `[a-z0-9_]` form used in metric names:
/// umlauts are transliterated (`ä→ae`, `ß→ss`), other diacritics stripped, and every
/// other run of characters becomes a single `_`. Returns "" if nothing usable is left.
pub fn normalize(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars().flat_map(char::to_lowercase) {
        let mapped: &str = match c {
            'a'..='z' | '0'..='9' => {
                if sep && !out.is_empty() {
                    out.push('_');
                }
                sep = false;
                out.push(c);
                continue;
            }
            'ä' | 'æ' => "ae",
            'ö' | 'œ' => "oe",
            'ü' => "ue",
            'ß' => "ss",
            'à' | 'á' | 'â' | 'ã' | 'å' | 'ā' => "a",
            'ç' | 'ć' | 'č' => "c",
            'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ě' => "e",
            'ì' | 'í' | 'î' | 'ï' => "i",
            'ñ' | 'ń' => "n",
            'ò' | 'ó' | 'ô' | 'õ' | 'ø' => "o",
            'š' | 'ś' => "s",
            'ù' | 'ú' | 'û' => "u",
            'ý' | 'ÿ' => "y",
            'ž' | 'ź' | 'ż' => "z",
            _ => {
                sep = true;
                continue;
            }
        };
        if sep && !out.is_empty() {
            out.push('_');
        }
        sep = false;
        out.push_str(mapped);
    }
    out
}

/// Skip states whose control name normalizes to nothing and make every series unique:
/// when two states would render with identical labels under the same metric name, later
/// ones (ordered by UUID, so the result is stable) get `_2`, `_3`, ... appended.
fn assign_names(raw: HashMap<String, StateMeta>) -> HashMap<String, StateMeta> {
    let mut entries: Vec<(String, StateMeta)> = raw.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut taken: HashSet<(String, String, String, String, String)> = HashSet::new();
    let mut out = HashMap::new();
    for (uuid, mut m) in entries {
        if m.name.is_empty() {
            tracing::warn!("skipping state {:?} of control {:?}: name has no usable characters", m.state, m.control);
            continue;
        }
        let key = |name: &str| (name.to_string(), m.state.clone(), m.room.clone(), m.category.clone(), m.ctype.clone());
        if taken.contains(&key(&m.name)) {
            let base = m.name.clone();
            let unique = (2..)
                .map(|n| format!("{base}_{n}"))
                .find(|candidate| !taken.contains(&key(candidate)))
                .expect("infinite range");
            tracing::warn!(
                "control {:?} (state {:?}) collides with another series; exporting it as {unique}",
                m.control, m.state
            );
            m.name = unique;
        }
        taken.insert(key(&m.name));
        out.insert(uuid, m);
    }
    out
}

/// Parse `YYYY-MM-DD HH:MM:SS` as seconds since the Unix epoch (UTC).
pub fn parse_timestamp(s: &str) -> Option<f64> {
    let (date, time) = s.trim().split_once(' ')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.split(':').map(|p| p.parse::<i64>().ok());
    let (hh, mm, ss) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    // days-from-civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + hh * 3600 + mm * 60 + ss) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "lastModified": "2024-05-02 10:33:07",
      "rooms": {"r1": {"name": "Kitchen"}},
      "cats":  {"c1": {"name": "Climate"}},
      "controls": {
        "ctl1": {"name": "Thermostat", "type": "IRoomControllerV2", "room": "r1", "cat": "c1",
                 "states": {"tempActual": "aaaaaaaa-0000-0000-0000000000000001",
                            "multi": ["aaaaaaaa-0000-0000-0000000000000002", "aaaaaaaa-0000-0000-0000000000000003"],
                            "single": ["aaaaaaaa-0000-0000-0000000000000004"]},
                 "subControls": {"sub1": {"name": "Heat", "type": "Switch",
                                          "states": {"active": "aaaaaaaa-0000-0000-0000000000000005"}}}},
        "ctl2": {"name": "No states", "type": "Info"}
      }
    }"#;

    #[test]
    fn flattens_states_with_labels() {
        let s = parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(s.states.len(), 5);
        let t = &s.states["aaaaaaaa-0000-0000-0000000000000001"];
        assert_eq!(
            (t.control.as_str(), t.state.as_str(), t.room.as_str(), t.category.as_str(), t.ctype.as_str()),
            ("Thermostat", "tempActual", "Kitchen", "Climate", "IRoomControllerV2")
        );
        assert_eq!(t.name, "thermostat");
        assert_eq!(s.states["aaaaaaaa-0000-0000-0000000000000005"].name, "thermostat_heat");
        assert_eq!(s.states["aaaaaaaa-0000-0000-0000000000000002"].state, "multi[0]");
        assert_eq!(s.states["aaaaaaaa-0000-0000-0000000000000003"].state, "multi[1]");
        assert_eq!(s.states["aaaaaaaa-0000-0000-0000000000000004"].state, "single");
        let sub = &s.states["aaaaaaaa-0000-0000-0000000000000005"];
        assert_eq!((sub.control.as_str(), sub.room.as_str(), sub.ctype.as_str()), ("Thermostat / Heat", "Kitchen", "Switch"));
        assert_eq!(s.version.as_deref(), Some("2024-05-02 10:33:07"));
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(normalize("Wohnzimmer Temperatur"), "wohnzimmer_temperatur");
        assert_eq!(normalize("Küche / Größe"), "kueche_groesse");
        assert_eq!(normalize("  Straße--Ost (2.OG) "), "strasse_ost_2_og");
        assert_eq!(normalize("Café Ñandú"), "cafe_nandu");
        assert_eq!(normalize("ÄÖÜ"), "aeoeue");
        assert_eq!(normalize("Parent / Sub"), "parent_sub");
        assert_eq!(normalize("°C"), "c");
        assert_eq!(normalize("---"), "");
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("Zähler 1"), "zaehler_1");
    }

    #[test]
    fn duplicates_get_stable_suffixes_and_empty_names_are_skipped() {
        let json = r#"{"rooms":{"r":{"name":"R"}},"controls":{
          "a":{"name":"Licht","type":"Switch","room":"r","states":{"active":"00000001-0000-0000-0000000000000001"}},
          "b":{"name":"licht","type":"Switch","room":"r","states":{"active":"00000001-0000-0000-0000000000000002"}},
          "c":{"name":"LICHT","type":"Switch","room":"r","states":{"active":"00000001-0000-0000-0000000000000003"}},
          "d":{"name":"Licht 2","type":"Switch","room":"r","states":{"active":"00000001-0000-0000-0000000000000004"}},
          "e":{"name":"---","type":"Switch","room":"r","states":{"active":"00000001-0000-0000-0000000000000005"}}
        }}"#;
        let s = parse(json.as_bytes()).unwrap();
        let name = |n: u8| s.states.get(&format!("00000001-0000-0000-000000000000000{n}")).map(|m| m.name.as_str());
        assert_eq!(name(1), Some("licht"));
        assert_eq!(name(2), Some("licht_2"));
        assert_eq!(name(3), Some("licht_3"));
        // "Licht 2" normalizes to licht_2, which is already taken by the duplicate.
        assert_eq!(name(4), Some("licht_2_2"));
        assert_eq!(name(5), None);
        // Same input, same names.
        assert_eq!(parse(json.as_bytes()).unwrap().states, s.states);
    }

    #[test]
    fn timestamp_parsing() {
        assert_eq!(parse_timestamp("1970-01-01 00:00:00"), Some(0.0));
        assert_eq!(parse_timestamp("2024-05-02 10:33:07"), Some(1714645987.0));
        assert_eq!(parse_timestamp("2000-03-01 00:00:01"), Some(951868801.0));
        assert_eq!(parse_timestamp("garbage"), None);
    }

    #[test]
    fn accepts_bom_and_reports_garbage() {
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(SAMPLE.as_bytes());
        assert_eq!(parse(&bom).unwrap().states.len(), 5);
        let err = format!("{:#}", parse(b"<html>nope").unwrap_err());
        assert!(err.contains("10 bytes") && err.contains("<html>"), "{err}");
    }

    #[test]
    fn tolerates_missing_sections() {
        let s = parse(b"{}").unwrap();
        assert!(s.states.is_empty() && s.version.is_none());
        assert!(parse(b"nope").is_err());
    }
}
