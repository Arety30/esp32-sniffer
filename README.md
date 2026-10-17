# esp32-sniffer

A Wi-Fi frame monitor by Syed Abrar Ali built around a NodeMCU-32S (ESP32). The board joins the home network to learn the channel, then switches to promiscuous mode and reports every 802.11 frame sent or received by one chosen device (or by everyone) over its serial port: direction, frame class and subtype, peer MAC, size, RSSI and whether the payload is encrypted, plus the raw header bytes. On the laptop side, `decode.py` turns those header bytes into readable 802.11 fields, `flowcap.py` watches the laptop's own traffic to recover the real destination hostnames from TLS handshakes, and `server.py` combines both into a live browser dashboard. The point is to see what a device actually does on the air (how often it talks, to whom, which streaming service is using the bandwidth) while making clear that WPA2 payloads stay encrypted: this is traffic analysis, not decryption.

## Where it is used

A learning and diagnostics tool on the owner's desk: the ESP32 sits on USB next to the laptop, and the dashboard shows the laptop's own radio activity frame by frame alongside a "where it actually goes" panel of live flows. It was used to understand Wi-Fi management/control/data traffic, to check which hosts a streaming session talks to, and to spot chatty background apps.

## How it works

### Firmware (`esp32-sniffer.ino`)

- Connects as a station using the SSID and password from `secrets.h` (20 s timeout, otherwise it sniffs channel 1). Joining is only a way to land on the right channel.
- Registers a promiscuous RX callback with all management/control/data filters enabled. Each callback parses the 24-byte header (`Hdr80211`: frame control, duration, addr1 receiver, addr2 transmitter, addr3, sequence).
- Filtering: `TARGET_MAC` selects one device; frames whose transmitter is the target are tagged `OUT`, frames addressed to it are `IN` (`SHOW_INCOMING`). An all-zero `TARGET_MAC` shows every device. CTS/ACK control frames (no transmitter address) and aggregated A-MPDU frames (reported by the SDK with no header) are counted but not listed.
- Records are queued from the callback (128-slot FreeRTOS queue; overflow is counted as "dropped") and printed in `loop()` as one human line (`time dir class subtype -> peer bytes dBm enc`) followed, when `DUMP_HEX` is on, by `RAW <hex>` with up to 40 header bytes. Every 5 seconds a summary line gives frames/bytes for the target, total frames on the channel, aggregated frames and drops.

### Decoder (`decode.py`)

Reads the serial device or a saved log. For each `RAW` line it parses the Frame Control word (version, type, subtype, To-DS/From-DS, retry, more-fragments, power-management, more-data, protected, order), picks the address roles according to the To-DS/From-DS combination (destination/source/BSSID, etc.), prints sequence and fragment numbers and, for QoS data, the TID. It annotates addresses that are broadcast, multicast or locally administered (randomised). The serial port is configured with `stty` and read as a raw file deliberately: opening it with pyserial toggles DTR/RTS, which resets an ESP32 into its bootloader.

### Flow capture (`flowcap.py`)

Opens an `AF_PACKET` raw socket on the Wi-Fi interface (`IFACE`, needs root), learns the laptop's own MAC and IPs, and for every IPv4/IPv6 TCP/UDP packet attributes bytes in or out to a `(proto, peer ip, peer port)` flow. On a TLS ClientHello it parses the `server_name` extension to get the real hostname; otherwise it resolves the IP with reverse DNS in a background thread. `snapshot()` groups flows by hostname, computes down/up kbit/s from the previous snapshot, expires flows idle for 90 s, and classifies each group as video, audio or web from hostname keywords and, failing that, bitrate thresholds (above 1.5 Mbit/s video, above 150 kbit/s audio/stream).

### Dashboard (`server.py`)

A dependency-free `ThreadingHTTPServer`:

| Route | Content |
| --- | --- |
| `/` | Single-page dashboard (inline HTML/CSS/JS): frame table with class filters, text filter, pause/clear, per-second rate, click-to-expand details; right panel of live flows with bitrate bars |
| `/stream` | Server-Sent Events: one JSON event per decoded frame (merged with the preceding metadata line) and `note` events for the 5-second summaries |
| `/flows` | `flowcap.snapshot()` as JSON, polled every second |
| `/conns` | Established sockets from `ss -tunHp` with process names and reverse-DNS names |

At startup it labels known MACs (broadcast, this laptop, entries from `ip neigh` mapped to their LAN IPs) so frames show "this laptop" or an IP instead of a bare address. `run-web.sh` starts it under `sudo` with the repo on `PYTHONPATH` so `flowcap` can open the raw socket.

## Setup

Hardware: NodeMCU-32S or any ESP32 dev board, USB cable, a 2.4 GHz Wi-Fi network.

Firmware:

1. Install the Arduino IDE (or arduino-cli) with the ESP32 board package.
2. Copy `secrets.h.example` semantics: create `secrets.h` next to the sketch with
   ```c
   #pragma once
   #define WIFI_SSID "YourNetwork"
   #define WIFI_PASS "YourPassword"
   ```
   (this file is private and must not be committed).
3. In the sketch set `TARGET_MAC` to the MAC of the device to follow (all zeros for everything), and `SHOW_INCOMING` / `DUMP_HEX` as wanted.
4. Select the board, upload at 115200 baud.

Laptop side: Python 3 (standard library only), `iproute2` (`ip`, `ss`), root for flow capture. Edit `IFACE = "wlo1"` in `flowcap.py` and the `/sys/class/net/wlo1/address` path in `server.py` to your wireless interface name. Optional: a udev rule that symlinks the board to `/dev/esp32` so the default device path in `run-web.sh` works.

## Usage

Serial monitor only:

```bash
stty -F /dev/ttyUSB0 115200 raw -echo -hupcl && cat /dev/ttyUSB0
```

Decode headers live, or from a saved capture:

```bash
python3 decode.py /dev/ttyUSB0
python3 decode.py capture.log
```

Sample decoded frame:

```
Frame 12
  Data / QoS Data   (ver 0)
  flags: toDS, PROTECTED (WPA2 payload encrypted)
  BSSID (AP)  : aa:bb:cc:dd:ee:ff
  source      : 11:22:33:44:55:66
  destination : ff:ff:ff:ff:ff:ff (multicast/broadcast)
  seq 1431  frag 0
  QoS: TID 0, normal
```

Dashboard:

```bash
./run-web.sh /dev/ttyUSB0 8799      # then open http://localhost:8799
```

## Project structure

```
esp32-sniffer/
├── esp32-sniffer.ino   # ESP32 firmware: join network, promiscuous capture, serial output
├── secrets.h           # WIFI_SSID / WIFI_PASS (private, not committed)
├── decode.py           # 802.11 header decoder for serial or log input
├── flowcap.py          # raw-socket flow capture with TLS SNI and bitrate classification
├── server.py           # SSE dashboard combining frames, labels and flows
└── run-web.sh          # start the dashboard as root with the right PYTHONPATH
```

## Limitations and notes

- Only the 802.11 header is captured (first 40 bytes); payloads are WPA2-encrypted and never decoded. Hostnames come from the laptop's own TLS handshakes, not from the air.
- The ESP32 sees one channel at a time (the one it joined) and cannot attribute aggregated A-MPDU frames to a sender; they only appear in the summary counts.
- Serial throughput limits how many frames can be reported; busy channels will show non-zero "dropped" counts.
- `flowcap.py` only observes the laptop running it, so the flow panel is meaningful when `TARGET_MAC` is the laptop itself.
- Category classification is heuristic (keyword lists and bitrate thresholds) and reverse DNS is often missing for CDN addresses.
- The dashboard binds to all interfaces (`0.0.0.0`) without authentication; run it on a trusted network or bind it to loopback.
- `server.py` contains a hard-coded filter for the laptop's own LAN address and MAC prefixes for the owner's access points in `label_mac`; replace or remove them for your network.
- Sniffing other people's traffic may be illegal where you live; use it only on networks and devices you own.
