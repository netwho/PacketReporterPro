# PacketReporter Pro — Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## v.0.2.1 — 2026-03-04

### Annotated Report — Full Section Parity with Detailed Report

The Annotated Report now includes every subsection present in the Detailed Report.

**Section 11 — IP Layer Analysis**
- Added **DSCP Distribution** pie chart between IP Protocol Distribution and TTL Distribution, with its own annotation sidebar explaining QoS/DSCP markings and traffic classes

**Section 12 — TCP Analysis**
- **TCP Summary table** extended with Window Size (Min / Max / Avg) and Segment Length (Min / Max / Avg) rows, matching the Detailed Report
- **12.1 TCP Options Negotiated** added as a continuation page: shows option presence (MSS, Window Scale, SACK, Timestamps, MPTCP, …) across observed SYN packets with percentage columns and a dedicated annotation sidebar
- **12.4 Top 10 Connections — Throughput & Response Time** added: renders at full page width with `IP:port(svc) ↔ IP:port(svc)` connection strings, proportional column widths (Connection 48%, numeric columns compact); annotation placed below the table
- **12.5 Top 10 Connections — TCP Flag Usage** added: per-connection SYN/FIN/RST/ACK/PSH counts at full page width; annotation placed below the table

### Annotated Report — Layout Improvements

- **Section 1 — PCAP File Summary:** increased gap before each subsection heading (File / Time / Statistics / Capture Overview / Project) from 4 pt to 14 pt for better visual separation
- **Section 1 — Project lines:** description lines now parse the first `:` in each line — the left side is rendered as a bold label, the right side as the value, matching the indentation of all other key-value rows in the section. Lines without `:` are shown as plain text at the value indent
- **12.4 / 12.5 annotation strips:** the horizontal annotation-below strip now has a **dynamic height** computed from the actual wrapped text. A `count_wrapped_lines()` helper mirrors the word-wrap logic without rendering, so the box is always tall enough to show "How to Read" in full regardless of content length

### Build System

- `build_plugin.sh` made fully parametric: accepts a Wireshark version tag as `$1` or `WS_TAG` env var (default `v4.6.3`); auto-clones the correct Wireshark source tree if not present; strips the output binary; copies to `installers/linux/packetreporterpro-ws{XY}.so`
- New `build_all_native.sh`: builds for Wireshark 4.2.14, 4.4.14, and 4.6.3 in sequence with a combined pass/fail summary — no Docker required
- Linux installer binaries updated for all three supported Wireshark series (stripped, ~313 KB each)

### New Annotation Constants

- `ann_ip_dscp` — DSCP Distribution
- `ann_tcp_opts` — TCP Options Negotiated
- `ann_tcp_throughput` — Top 10 Connections: Throughput & Response Time
- `ann_tcp_flags` — Top 10 Connections: TCP Flag Usage

---

## v.0.2.0 — 2026-03-04

### Reports

- **Project section on page 1** — the three cover-page description lines (customer, segment, notes) are now also printed in a dedicated "Project" subsection on the PCAP File Summary page (Section 1) in both Detailed and Annotated reports
- **TCP Analysis — connection readability** — Sections 12.4 and 12.5 now display full `IP:port(service) ↔ IP:port(service)` connection strings with service names for well-known ports (https, ssh, dns, rdp, mysql, …). The Connection column gets 48% of the table width; numeric columns are more compact. Connection components (`addr_a/b`, `port_a/b`) are stored at collection time and formatted at render time using a self-contained service-name lookup (no platform dependencies)
- **Annotated report — adaptive annotation placement** — when a section's right-side sidebar would be too short (< 80 pt), the annotation is automatically rendered as a full-width horizontal strip below the section content instead

### GUI / Logo

- **Logo dimension hint** — label below the Choose Logo button shows the recommended size (900 × 300 px, 3:1 ratio)
- **Logo validation on pick** — shows actual dimensions and ratio with a green "OK" or orange warning; prompts the user if the image is too small or the wrong ratio
- **Auto-save as `Logo_custom.png`** — picked logos are immediately converted to PNG via `QImage` (fixes JPG/BMP support — Cairo only reads PNG) and saved to `~/.packet_reporter/Logo_custom.png`. Loaded automatically on the next session
- **Default Logo button** — reverts to the factory-installed `Logo.png` from `~/.packet_reporter/`
- `config_reader_load()` updated: tries `Logo_custom.png` first, falls back to `Logo.png`

### Internal

- `table_def_t` extended with optional `col_ratios[]` array for proportional column widths; `NULL` keeps equal-width behaviour — all existing tables unaffected
- `tcp_stream_rtt_t` extended with `addr_a[64]`, `addr_b[64]`, `port_a`, `port_b` for readable connection display
- `collector_top_streams_by_bytes()` added — returns top-N TCP streams sorted by byte count

---

## v.0.1.1 — 2025-12-01

- Linux stability fixes: resolved Wireshark API differences between 4.2 / 4.4 / 4.6 that could crash Wireshark during report generation
- Initial public release binaries for macOS (universal arm64+x86_64), Linux (per WS version), Windows

---

## v.0.1.0 — 2025-11-15

- Initial public release
- Native Wireshark epan plugin (C/C++) replacing the Lua-based PacketReporter
- Cairo PDF rendering, Qt6 settings window
- Network Analysis: Summary, Detailed, and Annotated reports
- WiFi / 802.11 Analysis: Summary, Detailed, and Annotated reports
- macOS universal binary (arm64 + x86_64)
- Linux binaries for Wireshark 4.2, 4.4, 4.6
