#!/usr/bin/python3
"""Laptop-side flow capture for the ESP32 monitor.

Uses an AF_PACKET raw socket on wlo1 (needs root) to watch this laptop's
own traffic in both directions. For each connection it records bytes in and
out, pulls the real destination hostname from the TLS SNI in the clear
ClientHello, and classifies the flow (video / audio / web / quic / other)
from the hostname and its bandwidth. It never reads the encrypted payload.
"""
import socket, struct, threading, time, subprocess, re

IFACE = "wlo1"
OUR_IPS = set()
OUR_MACS = set()

flows = {}          # (proto, peer_ip, peer_port) -> dict
ip2host = {}        # peer_ip -> hostname (from SNI, then rDNS)
lock = threading.Lock()

VIDEO = ("googlevideo", "nflxvideo", "ttvnw", "vimeocdn", "dmcdn", "video",
         "vod", ".mux.com", "fbcdn", "gvt1", "akamaized")
AUDIO = ("scdn.co", "spotify", "sndcdn", "soundcloud", "pandora", "audio",
         "music", "deezer", "podcast")

def _load_identity():
    try:
        OUR_MACS.add(open("/sys/class/net/%s/address" % IFACE).read().strip().lower())
    except Exception:
        pass
    try:
        out = subprocess.run(["ip", "-o", "addr", "show", IFACE],
                             capture_output=True, text=True).stdout
        for m in re.finditer(r"inet6?\s+([0-9a-fA-F:.]+)/", out):
            OUR_IPS.add(m.group(1))
    except Exception:
        pass
    OUR_IPS.update({"127.0.0.1", "::1"})

def _rdns(ip):
    def work():
        try:
            h = socket.gethostbyaddr(ip)[0]
            with lock:
                ip2host.setdefault(ip, h)
        except Exception:
            with lock:
                ip2host.setdefault(ip, "")
    threading.Thread(target=work, daemon=True).start()

def parse_sni(p):
    try:
        if len(p) < 44 or p[0] != 0x16:
            return None
        hs = p[5:]
        if hs[0] != 0x01:            # ClientHello
            return None
        i = 4 + 2 + 32               # hs header + version + random
        i += 1 + hs[i]               # session id
        i += 2 + int.from_bytes(hs[i:i+2], "big")   # cipher suites
        i += 1 + hs[i]               # compression
        ext_len = int.from_bytes(hs[i:i+2], "big"); i += 2
        end = i + ext_len
        while i + 4 <= end and i + 4 <= len(hs):
            et = int.from_bytes(hs[i:i+2], "big")
            el = int.from_bytes(hs[i+2:i+4], "big"); i += 4
            if et == 0x0000:         # server_name
                sni = hs[i:i+el]
                nlen = int.from_bytes(sni[3:5], "big")
                return sni[5:5+nlen].decode("utf-8", "ignore")
            i += el
    except Exception:
        return None
    return None

def _touch(proto, pip, pport, host, nbytes, inbound):
    key = (proto, pip, pport)
    with lock:
        f = flows.get(key)
        if not f:
            f = {"proto": proto, "ip": pip, "port": pport, "host": "",
                 "bin": 0, "bout": 0, "first": time.time(), "last": 0}
            flows[key] = f
        if host:
            f["host"] = host
        elif not f["host"]:
            f["host"] = ip2host.get(pip, "")
        if inbound:
            f["bin"] += nbytes
        else:
            f["bout"] += nbytes
        f["last"] = time.time()

def _handle_ip(proto, src, dst, l4, total):
    if src in OUR_IPS:
        inbound, pip = False, dst
    elif dst in OUR_IPS:
        inbound, pip = True, src
    else:
        return
    if len(l4) < 4:
        return
    sport = int.from_bytes(l4[0:2], "big")
    dport = int.from_bytes(l4[2:4], "big")
    pport = dport if not inbound else sport
    host = None
    if proto == 6:                                  # TCP
        if len(l4) >= 13:
            off = (l4[12] >> 4) * 4
            payload = l4[off:]
            if payload[:1] == b"\x16":
                host = parse_sni(payload)
    pname = "quic" if (proto == 17 and pport == 443) else None
    if host:
        with lock:
            ip2host[pip] = host
    elif pip not in ip2host and not pip.startswith(("192.168.", "10.", "fe80", "172.16.")):
        _rdns(pip)
    _touch(proto, pip, pport, host, total, inbound)

def _run():
    _load_identity()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    except Exception:
        pass
    s.bind((IFACE, 0))
    while True:
        try:
            pkt = s.recv(65535)
        except Exception:
            time.sleep(0.2); continue
        if len(pkt) < 14:
            continue
        et = int.from_bytes(pkt[12:14], "big")
        off = 14
        if et == 0x8100:                    # VLAN tag
            et = int.from_bytes(pkt[16:18], "big"); off = 18
        d = pkt[off:]
        try:
            if et == 0x0800:                # IPv4
                ihl = (d[0] & 0xF) * 4
                proto = d[9]
                total = int.from_bytes(d[2:4], "big")
                src = socket.inet_ntoa(d[12:16])
                dst = socket.inet_ntoa(d[16:20])
                if proto in (6, 17):
                    _handle_ip(proto, src, dst, d[ihl:], total)
            elif et == 0x86DD:              # IPv6
                proto = d[6]
                total = int.from_bytes(d[4:6], "big") + 40
                src = socket.inet_ntop(socket.AF_INET6, d[8:24])
                dst = socket.inet_ntop(socket.AF_INET6, d[24:40])
                if proto in (6, 17):
                    _handle_ip(proto, src, dst, d[40:], total)
        except Exception:
            continue

_prev = {}          # gid -> (t, bin, bout)

def classify(host, down_kbps):
    h = (host or "").lower()
    if any(x in h for x in VIDEO):
        return "video"
    if any(x in h for x in AUDIO):
        return "audio"
    if down_kbps > 1500:
        return "video (by bitrate)"
    if down_kbps > 150:
        return "audio/stream (by bitrate)"
    return "web"

def snapshot():
    now = time.time()
    groups = {}                     # gid(host or ip) -> aggregate
    with lock:
        stale = [k for k, f in flows.items() if now - f["last"] > 90]
        for k in stale:
            del flows[k]
        for f in flows.values():
            gid = f["host"] or f["ip"]
            g = groups.setdefault(gid, {"host": f["host"], "ip": f["ip"],
                                        "bin": 0, "bout": 0, "conns": 0,
                                        "proto": f["proto"], "last": 0})
            g["bin"] += f["bin"]; g["bout"] += f["bout"]; g["conns"] += 1
            g["last"] = max(g["last"], f["last"])
    rows = []
    for gid, g in groups.items():
        pt, pin, pout = _prev.get(gid, (now - 1, g["bin"], g["bout"]))
        dt = max(now - pt, 0.001)
        down = max(g["bin"] - pin, 0) * 8 / dt / 1000.0     # kbps
        up   = max(g["bout"] - pout, 0) * 8 / dt / 1000.0
        _prev[gid] = (now, g["bin"], g["bout"])
        proto = "quic" if (g["proto"] == 17 and 0) else ("udp" if g["proto"] == 17 else "tcp")
        rows.append({
            "host": g["host"], "ip": g["ip"], "conns": g["conns"],
            "down_kbps": round(down, 1), "up_kbps": round(up, 1),
            "bin": g["bin"], "bout": g["bout"], "proto": proto,
            "cat": classify(g["host"] or g["ip"], down),
            "idle": round(now - g["last"], 1),
        })
    for gid in [k for k in _prev if k not in groups]:
        _prev.pop(gid, None)
    rows.sort(key=lambda r: (r["down_kbps"] + r["up_kbps"]), reverse=True)
    return rows[:50]

def start():
    threading.Thread(target=_run, daemon=True).start()

if __name__ == "__main__":
    start()
    time.sleep(3)
    for r in snapshot():
        print(r)
