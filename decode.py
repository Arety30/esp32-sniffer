#!/usr/bin/python3
"""Decode 802.11 frame headers captured by the ESP32 sniffer.

Reads the sketch's serial output (or a saved log). For every "RAW <hex>"
line it parses the parts of the 802.11 header that are transmitted in the
clear: the Frame Control field, the address fields and their roles, the
sequence/fragment numbers and the QoS control word. The frame body stays
WPA2-encrypted and is not touched.

Usage:
  python3 decode.py                 # live, reads /dev/ttyUSB0 at 115200
  python3 decode.py /dev/ttyUSB0
  python3 decode.py somelog.txt     # decode a previously saved capture
"""
import sys, os

TYPE = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
SUBTYPE = {
    (0, 0): "Association Request",  (0, 1): "Association Response",
    (0, 2): "Reassociation Request",(0, 3): "Reassociation Response",
    (0, 4): "Probe Request",        (0, 5): "Probe Response",
    (0, 8): "Beacon",               (0, 9): "ATIM",
    (0, 10): "Disassociation",      (0, 11): "Authentication",
    (0, 12): "Deauthentication",    (0, 13): "Action",
    (1, 8): "Block Ack Request",    (1, 9): "Block Ack",
    (1, 10): "PS-Poll",             (1, 11): "RTS",
    (1, 12): "CTS",                 (1, 13): "ACK",
    (1, 14): "CF-End",              (1, 15): "CF-End+CF-Ack",
    (2, 0): "Data",                 (2, 4): "Null (no data)",
    (2, 8): "QoS Data",             (2, 12): "QoS Null",
}

def mac(b):
    return ":".join("%02x" % x for x in b) if len(b) == 6 else "-"

def oui(b):
    # crude vendor hint from the first three bytes / locally-administered bit
    if len(b) != 6:
        return ""
    if b[0] & 0x01:
        return " (multicast/broadcast)" if b == b"\xff"*6 else " (group/mcast)"
    if b[0] & 0x02:
        return " (locally-administered / randomized)"
    return ""

def decode(hexstr):
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(b) < 2:
        return None
    fc = b[0] | (b[1] << 8)
    ver = fc & 0x3
    typ = (fc >> 2) & 0x3
    sub = (fc >> 4) & 0xF
    tods   = bool(fc & 0x0100)
    fromds = bool(fc & 0x0200)
    mf     = bool(fc & 0x0400)
    retry  = bool(fc & 0x0800)
    pwr    = bool(fc & 0x1000)
    more   = bool(fc & 0x2000)
    prot   = bool(fc & 0x4000)
    order  = bool(fc & 0x8000)

    out = []
    tname = TYPE.get(typ, "?")
    sname = SUBTYPE.get((typ, sub), "subtype %d" % sub)
    out.append("  %s / %s   (ver %d)" % (tname, sname, ver))

    flags = []
    if tods:   flags.append("toDS")
    if fromds: flags.append("fromDS")
    if retry:  flags.append("retry")
    if mf:     flags.append("more-frag")
    if more:   flags.append("more-data")
    if pwr:    flags.append("pwr-mgmt")
    if order:  flags.append("ordered")
    flags.append("PROTECTED (WPA2 payload encrypted)" if prot else "not protected")
    out.append("  flags: " + ", ".join(flags))

    # address layout depends on toDS/fromDS
    a1 = b[4:10]  if len(b) >= 10 else b""
    a2 = b[10:16] if len(b) >= 16 else b""
    a3 = b[16:22] if len(b) >= 22 else b""
    if typ == 1:  # control frames: RTS has a1+a2, ACK/CTS only a1
        out.append("  receiver : %s%s" % (mac(a1), oui(a1)))
        if a2:
            out.append("  transmit : %s%s" % (mac(a2), oui(a2)))
    else:
        if not tods and not fromds:
            role = ("destination", "source", "BSSID")
        elif not tods and fromds:
            role = ("destination", "BSSID (AP)", "source")
        elif tods and not fromds:
            role = ("BSSID (AP)", "source", "destination")
        else:
            role = ("receiver", "transmitter", "destination")
        for r, a in zip(role, (a1, a2, a3)):
            if a:
                out.append("  %-11s: %s%s" % (r, mac(a), oui(a)))
        if len(b) >= 24:
            sc = b[22] | (b[23] << 8)
            out.append("  seq %d  frag %d" % (sc >> 4, sc & 0xF))
        if typ == 2 and (sub & 0x8) and len(b) >= 26:  # QoS data
            qos = b[24] | (b[25] << 8)
            out.append("  QoS: TID %d, %s" % (qos & 0xF,
                       "EOSP" if qos & 0x10 else "normal"))
    return "\n".join(out)

def source():
    arg = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    if os.path.exists(arg) and not arg.startswith("/dev/"):
        for ln in open(arg, encoding="utf-8", errors="ignore"):
            yield ln
        return
    # Read the serial device like `cat` does. Opening it through pyserial
    # toggles DTR/RTS, which on an ESP32 asserts the auto-reset line and can
    # drop the board into its bootloader. Configuring it with stty and then
    # reading the raw fd leaves those pins alone, so the sketch keeps running.
    os.system("stty -F %s 115200 raw -echo -hupcl" % arg)
    print("# reading live from %s — Ctrl-C to stop\n" % arg)
    buf = b""
    with open(arg, "rb", buffering=0) as f:
        while True:
            chunk = f.read(256)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                yield line.decode("utf-8", errors="ignore")

def main():
    n = 0
    try:
        for line in source():
            line = line.strip()
            if line.startswith("RAW "):
                d = decode(line[4:])
                if d:
                    n += 1
                    print("Frame %d" % n)
                    print(d)
                    print()
            elif line.startswith("----") or line.startswith("=="):
                print(line)
    except KeyboardInterrupt:
        print("\n# stopped after %d frames" % n)

if __name__ == "__main__":
    main()
