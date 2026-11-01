//! Shared state: latest values pushed by the Miniserver plus exporter health
//! counters, rendered in the Prometheus text exposition format.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::{TextEvent, ValueEvent};
use crate::structure::{StateMeta, Structure};

#[derive(Default)]
struct Inner {
    structure: Structure,
    values: HashMap<String, f64>,
    texts: HashMap<String, String>,
    connected: bool,
    last_event: Option<f64>,
    reconnects: u64,
    auth_failures: u64,
    skipped: u64,
}

#[derive(Default)]
pub struct Store {
    inner: Mutex<Inner>,
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the structure. Series of controls that no longer exist are dropped.
    pub fn set_structure(&self, s: Structure) {
        let mut g = self.lock();
        g.values.retain(|u, _| s.states.contains_key(u));
        g.texts.retain(|u, _| s.states.contains_key(u));
        g.structure = s;
    }

    pub fn apply_values(&self, events: Vec<ValueEvent>) {
        let mut g = self.lock();
        for e in events {
            if g.structure.states.contains_key(&e.uuid) {
                g.values.insert(e.uuid, e.value);
                g.last_event = Some(now());
            } else {
                g.skipped += 1;
            }
        }
    }

    pub fn apply_texts(&self, events: Vec<TextEvent>) {
        let mut g = self.lock();
        for e in events {
            if g.structure.states.contains_key(&e.uuid) {
                g.texts.insert(e.uuid, e.text);
                g.last_event = Some(now());
            } else {
                g.skipped += 1;
            }
        }
    }

    pub fn set_connected(&self, connected: bool) {
        self.lock().connected = connected;
    }

    pub fn inc_reconnects(&self) {
        self.lock().reconnects += 1;
    }

    pub fn inc_auth_failures(&self) {
        self.lock().auth_failures += 1;
    }

    pub fn render(&self) -> String {
        let g = self.lock();
        let mut out = String::new();

        let metric = |out: &mut String, name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}");
        };
        metric(&mut out, "loxone_connected", "gauge",
            "1 if the WebSocket to the Miniserver is up and authenticated, else 0.",
            (g.connected as u8).to_string());
        metric(&mut out, "loxone_last_event_timestamp_seconds", "gauge",
            "Unix time of the last value or text event received (0 if none yet).",
            fmt_f64(g.last_event.unwrap_or(0.0)));
        metric(&mut out, "loxone_reconnects_total", "counter",
            "Number of times the Miniserver connection ended and was retried.",
            g.reconnects.to_string());
        metric(&mut out, "loxone_auth_failures_total", "counter",
            "Number of failed authentication attempts.", g.auth_failures.to_string());
        metric(&mut out, "loxone_skipped_events_total", "counter",
            "Events dropped because their UUID is not in the structure file.",
            g.skipped.to_string());
        metric(&mut out, "loxone_structure_last_modified_timestamp_seconds", "gauge",
            "lastModified of the loaded Loxone config (Miniserver local time read as UTC).",
            fmt_f64(g.structure.last_modified_epoch.unwrap_or(0.0)));

        // One metric family per normalized control name; HELP/TYPE once per family.
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for uuid in sorted_keys(&g.values) {
            if let Some(m) = g.structure.states.get(&uuid) {
                values
                    .entry(format!("loxone_value_{}", m.name))
                    .or_default()
                    .push(format!("{{{}}} {}", labels(m), fmt_f64(g.values[&uuid])));
            }
        }
        let mut texts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for uuid in sorted_keys(&g.texts) {
            if let Some(m) = g.structure.states.get(&uuid) {
                texts
                    .entry(format!("loxone_text_{}_info", m.name))
                    .or_default()
                    .push(format!("{{{},text=\"{}\"}} 1", labels(m), escape(&g.texts[&uuid])));
            }
        }
        for (name, lines) in &values {
            let _ = writeln!(out, "# HELP {name} Current numeric value of a Miniserver control state.\n# TYPE {name} gauge");
            for l in lines {
                let _ = writeln!(out, "{name}{l}");
            }
        }
        for (name, lines) in &texts {
            let _ = writeln!(out, "# HELP {name} Current text of a Miniserver control state, carried in the text label.\n# TYPE {name} gauge");
            for l in lines {
                let _ = writeln!(out, "{name}{l}");
            }
        }
        out
    }
}

fn sorted_keys<V>(m: &HashMap<String, V>) -> Vec<String> {
    let mut k: Vec<String> = m.keys().cloned().collect();
    k.sort();
    k
}

fn labels(m: &StateMeta) -> String {
    format!(
        "state=\"{}\",room=\"{}\",category=\"{}\",type=\"{}\"",
        escape(&m.state), escape(&m.room), escape(&m.category), escape(&m.ctype)
    )
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let s = Store::new();
        let mut st = Structure::default();
        st.states.insert("u1".into(), StateMeta {
            control: "Living Room".into(), name: "living_room".into(), state: "temp".into(), room: "R\"x".into(),
            category: "C".into(), ctype: "T".into(),
        });
        st.states.insert("u2".into(), StateMeta {
            control: "Door".into(), name: "door".into(), state: "text".into(), room: "".into(), category: "".into(), ctype: "".into(),
        });
        s.set_structure(st);
        s
    }

    #[test]
    fn renders_values_texts_and_health() {
        let s = store();
        s.apply_values(vec![
            ValueEvent { uuid: "u1".into(), value: 21.5 },
            ValueEvent { uuid: "nope".into(), value: 1.0 },
        ]);
        s.apply_texts(vec![TextEvent { uuid: "u2".into(), text: "a\"b\\c\nd".into() }]);
        s.set_connected(true);
        let out = s.render();
        assert!(out.contains("loxone_connected 1\n"));
        assert!(out.contains("loxone_skipped_events_total 1\n"));
        assert!(out.contains(r#"loxone_value_living_room{state="temp",room="R\"x",category="C",type="T"} 21.5"#));
        assert!(out.contains(r#"loxone_text_door_info{state="text",room="",category="",type="",text="a\"b\\c\nd"} 1"#));
        assert!(!out.contains("uuid=") && !out.contains("control="));
        assert_eq!(out.matches("# TYPE loxone_value_living_room gauge").count(), 1);
        assert!(!out.contains("loxone_last_event_timestamp_seconds 0\n"));
    }

    #[test]
    fn values_survive_disconnect_and_drop_with_structure() {
        let s = store();
        s.apply_values(vec![ValueEvent { uuid: "u1".into(), value: 1.0 }]);
        s.set_connected(false);
        assert!(s.render().contains("loxone_connected 0\n"));
        assert!(s.render().contains("loxone_value_living_room{"));
        s.set_structure(Structure::default());
        assert!(!s.render().contains("loxone_value_"));
    }

    #[test]
    fn same_name_in_several_rooms_shares_one_family() {
        let s = Store::new();
        let mut st = Structure::default();
        for (u, room) in [("u1", "Kitchen"), ("u2", "Bath")] {
            st.states.insert(u.into(), StateMeta {
                control: "Temp".into(), name: "temp".into(), state: "actual".into(),
                room: room.into(), category: "".into(), ctype: "".into(),
            });
        }
        s.set_structure(st);
        s.apply_values(vec![
            ValueEvent { uuid: "u1".into(), value: 20.0 },
            ValueEvent { uuid: "u2".into(), value: 22.0 },
        ]);
        let out = s.render();
        assert_eq!(out.matches("# TYPE loxone_value_temp gauge").count(), 1);
        assert!(out.contains(r#"loxone_value_temp{state="actual",room="Kitchen",category="",type=""} 20"#));
        assert!(out.contains(r#"loxone_value_temp{state="actual",room="Bath",category="",type=""} 22"#));
    }

    #[test]
    fn special_floats() {
        assert_eq!(fmt_f64(f64::NAN), "NaN");
        assert_eq!(fmt_f64(f64::INFINITY), "+Inf");
        assert_eq!(fmt_f64(f64::NEG_INFINITY), "-Inf");
        assert_eq!(fmt_f64(3.0), "3");
    }
}
