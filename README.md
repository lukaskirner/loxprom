# loxprom

Single-binary Prometheus exporter for a Loxone Miniserver (Gen 2). It logs in over the
Miniserver's WebSocket (`wss://`, token auth), subscribes to push events and serves the
latest values on `/metrics`. Scrapes never touch the Miniserver.

## Run

```sh
export LOXONE_PASSWORD=...            # env only, never a CLI flag
loxprom --host 192.168.1.5 --user prometheus \
        --tls-server-name 192-168-1-5.<serial>.dyndns.loxonecloud.com
```

| Flag | Env | Default |
|---|---|---|
| `--host` | `LOXONE_HOST` | required |
| `--port` | `LOXONE_PORT` | `443` |
| `--user` | `LOXONE_USER` | required |
| – | `LOXONE_PASSWORD` | required |
| `--listen` | `LOXPROM_LISTEN` | `0.0.0.0:9876` |
| `--tls-server-name` | `LOXONE_TLS_SERVER_NAME` | the `--host` value |
| `--tls-insecure` | `LOXONE_TLS_INSECURE` | off (verify certificate) |
| `--structure-poll-secs` | `LOXONE_STRUCTURE_POLL_SECS` | `60` |

Use a dedicated read-only Miniserver user. After repeated failed logins Loxone locks the
user, so the exporter waits 5 minutes after an authentication failure before retrying.
The session token is refreshed (`getkey` + `refreshjwt`) after half its remaining
lifetime, at least every 30 minutes, so the connection is not dropped when it expires.

## Metrics

Every control gets its own metric name, derived from the control name in `LoxAPP3.json`:

- `loxone_value_<control>{state,room,category,type}`: numeric states, plain gauge, no units.
- `loxone_text_<control>_info{state,room,category,type,text}` = 1: current text of text states.
- Health (alert on these): `loxone_connected`, `loxone_last_event_timestamp_seconds`,
  `loxone_reconnects_total`, `loxone_auth_failures_total`, `loxone_skipped_events_total`,
  `loxone_structure_last_modified_timestamp_seconds`.

Example: a control "Wohnzimmer / Temperatur" with state `tempActual` in room "Wohnzimmer" becomes
`loxone_value_wohnzimmer_temperatur{state="tempActual",room="Wohnzimmer",category="Klima",type="IRoomControllerV2"}`.

Name normalization: lowercase; `ä ö ü ß` become `ae oe ue ss`; other diacritics are stripped;
every other run of characters becomes one `_`. Controls whose name normalizes to nothing are
skipped (with a warning). Two states that would produce identical series get `_2`, `_3`, ...
appended to the name, ordered by UUID, with a warning in the log. Renaming a control in Loxone
Config therefore renames its metric.

**The Miniserver user needs access to the controls.** Loxone filters `LoxAPP3.json` by user
rights; a user without access gets an empty `controls` section and the exporter logs
`loaded structure: 0 states`.

While the connection is down the last values stay on `/metrics` and `loxone_connected` is 0.
Every `--structure-poll-secs` the exporter checks `LoxAPPversion3`; on a change it reloads
the structure and series of removed controls disappear.

## Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GHCR by CI:
`latest` from `main`, semver tags from `v*` git tags, plus `sha-<commit>`.

```sh
docker run -d -p 9876:9876 -e LOXONE_HOST=192.168.1.5 -e LOXONE_USER=prometheus \
  -e LOXONE_PASSWORD=... ghcr.io/lukaskirner/loxprom:latest
```

## Build

```sh
cargo build --release                                   # normal binary
CC_aarch64_unknown_linux_musl=musl-gcc \
  cargo build --release --target aarch64-unknown-linux-musl   # static (needs musl-tools)
```
