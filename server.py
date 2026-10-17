#!/usr/bin/python3
"""Live web dashboard for the ESP32 802.11 sniffer.

Reads the sketch's serial output, decodes each frame's 802.11 header, and
streams the decoded records to a browser over Server-Sent Events. It also
labels known device MACs and shows this laptop's live outbound connections
(the real destinations, since WiFi payloads are WPA2-encrypted).

Run:  /usr/bin/python3 server.py [/dev/ttyUSB1] [port]
"""
import json, os, re, sys, threading, queue, time, subprocess, socket
import flowcap
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEV  = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8799

TYPE = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
CLS  = {0: "MGMT", 1: "CTRL", 2: "DATA", 3: "EXT"}
SUBTYPE = {
    (0,0):"Association Request",(0,1):"Association Response",
    (0,2):"Reassociation Request",(0,3):"Reassociation Response",
    (0,4):"Probe Request",(0,5):"Probe Response",(0,8):"Beacon",(0,9):"ATIM",
    (0,10):"Disassociation",(0,11):"Authentication",(0,12):"Deauthentication",
    (0,13):"Action",(1,8):"Block Ack Request",(1,9):"Block Ack",(1,10):"PS-Poll",
    (1,11):"RTS",(1,12):"CTS",(1,13):"ACK",(1,14):"CF-End",(1,15):"CF-End+CF-Ack",
    (2,0):"Data",(2,4):"Null (no data)",(2,8):"QoS Data",(2,12):"QoS Null",
}

# --- known-device labels (built at startup from the system's own tables) ----
LABELS = {}
def build_labels():
    LABELS["ff:ff:ff:ff:ff:ff"] = "broadcast"
    try:
        LABELS[open("/sys/class/net/wlo1/address").read().strip()] = "this laptop"
    except Exception:
        pass
    try:
        neigh = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        for ln in neigh.splitlines():
            p = ln.split()
            if len(p) >= 5 and ":" in p[4]:
                LABELS.setdefault(p[4].lower(), p[0])   # MAC -> its LAN IP
    except Exception:
        pass
def label_mac(m):
    m = m.lower()
    if m in LABELS:
        return LABELS[m]
    # ANZAR_WiFi router radios seen on the air
    if m.startswith("50:2f:54:67:d2") or m.startswith("0c:88:32:d8:f7"):
        return "router / AP"
    b0 = int(m[:2], 16) if len(m) >= 2 else 0
    if m == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if b0 & 0x01:
        return "multicast"
    if b0 & 0x02:
        return "randomized"
    return ""

def mac(b):
    return ":".join("%02x" % x for x in b) if len(b) == 6 else "-"

def decode(hexstr):
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(b) < 2:
        return None
    fc = b[0] | (b[1] << 8)
    typ = (fc >> 2) & 0x3
    sub = (fc >> 4) & 0xF
    tods, fromds = bool(fc & 0x0100), bool(fc & 0x0200)
    rec = {"cls": CLS.get(typ, "?"), "type": TYPE.get(typ, "?"),
           "sub": SUBTYPE.get((typ, sub), "subtype %d" % sub),
           "prot": bool(fc & 0x4000), "flags": [], "addrs": []}
    for bit, nm in ((0x0100,"toDS"),(0x0200,"fromDS"),(0x0800,"retry"),
                    (0x0400,"more-frag"),(0x2000,"more-data"),
                    (0x1000,"pwr-mgmt"),(0x8000,"ordered")):
        if fc & bit:
            rec["flags"].append(nm)
    a1, a2, a3 = b[4:10], b[10:16], b[16:22]
    def entry(role, a):
        s = mac(a)
        return {"role": role, "mac": s, "label": label_mac(s)}
    if typ == 1:
        if len(a1) == 6: rec["addrs"].append(entry("receiver", a1))
        if len(a2) == 6: rec["addrs"].append(entry("transmitter", a2))
    else:
        if not tods and not fromds: roles = ("destination","source","BSSID")
        elif not tods and fromds:   roles = ("destination","BSSID (AP)","source")
        elif tods and not fromds:   roles = ("BSSID (AP)","source","destination")
        else:                       roles = ("receiver","transmitter","destination")
        for r, a in zip(roles, (a1, a2, a3)):
            if len(a) == 6: rec["addrs"].append(entry(r, a))
        if len(b) >= 24:
            sc = b[22] | (b[23] << 8)
            rec["seq"], rec["frag"] = sc >> 4, sc & 0xF
        if typ == 2 and (sub & 0x8) and len(b) >= 26:
            rec["tid"] = (b[24] | (b[25] << 8)) & 0xF
    # from = transmitter (addr2), to = receiver (addr1) — the L2 hop
    def pick(*names):
        for nm in names:
            for a in rec["addrs"]:
                if a["role"] == nm:
                    return {"mac": a["mac"], "label": a["label"]}
        return None
    rec["src"] = pick("transmitter", "source")
    rec["dst"] = pick("receiver", "destination", "BSSID (AP)", "BSSID")
    return rec

META = re.compile(
    r"^\s*(\d+)\.(\d+)\s+(OUT|IN)\s+(MGMT|CTRL|DATA|EXT)\s+(\S+)\s+->\s+"
    r"([0-9a-f:]{17})\s+(\d+)\s*B\s+(-?\d+)\s*dBm\s+(\w+)")

subs, subs_lock = [], threading.Lock()
state = {"info": ""}

def broadcast(obj):
    data = json.dumps(obj)
    with subs_lock:
        for q in list(subs):
            try: q.put_nowait(data)
            except queue.Full: pass

def reader():
    while True:
        if not os.path.exists(DEV):
            state["info"] = "waiting for %s" % DEV
            time.sleep(1); continue
        try:
            os.system("stty -F %s 115200 raw -echo -hupcl 2>/dev/null" % DEV)
            with open(DEV, "rb", buffering=0) as f:
                buf, pending, n = b"", None, 0
                while True:
                    chunk = f.read(256)
                    if not chunk: continue
                    buf += chunk
                    while b"\n" in buf:
                        raw, buf = buf.split(b"\n", 1)
                        line = raw.decode("utf-8", "ignore").strip()
                        if not line: continue
                        m = META.match(line)
                        if m:
                            pending = {"t": float("%s.%s" % (m.group(1), m.group(2))),
                                       "dir": m.group(3), "len": int(m.group(7)),
                                       "rssi": int(m.group(8))}
                        elif line.startswith("RAW "):
                            d = decode(line[4:])
                            if d and pending:
                                n += 1; d.update(pending); d["n"] = n; pending = None
                                broadcast({"ev": "frame", "f": d})
                        elif "summary" in line:
                            broadcast({"ev": "note", "text": line})
        except Exception as e:
            state["info"] = "serial error: %s" % e
            time.sleep(1)

# --- outbound connections from this laptop (the real destinations) ----------
dns_cache, dns_lock = {}, threading.Lock()
def resolve_async(ip):
    with dns_lock:
        if ip in dns_cache: return
        dns_cache[ip] = None
    def work():
        try: h = socket.gethostbyaddr(ip)[0]
        except Exception: h = ""
        with dns_lock: dns_cache[ip] = h
    t = threading.Thread(target=work, daemon=True); t.start()

def is_lan(ip):
    return (ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1"
            or ip.startswith("172.16.") or ip.startswith("169.254.")
            or ip.startswith("fe80") or ip == "::1")

def conns():
    try:
        out = subprocess.run(["ss","-tunHp","state","established"],
                             capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return []
    agg = {}
    for ln in out.splitlines():
        p = ln.split()
        if len(p) < 5: continue
        proto, peer = p[0], p[4]
        if "]" in peer: ip, port = peer.rsplit("]:", 1); ip = ip.strip("[")
        elif peer.count(":") == 1: ip, port = peer.rsplit(":", 1)
        else: continue
        ip = ip.split("%")[0]
        if ip in ("0.0.0.0", "*", "") or ip.startswith("LAN_IP"): continue
        pm = re.search(r'"([^"]+)"', ln)
        proc = pm.group(1) if pm else ""
        key = (ip, port, proc)
        agg[key] = agg.get(key, 0) + 1
        if not is_lan(ip): resolve_async(ip)
    rows = []
    for (ip, port, proc), c in agg.items():
        with dns_lock: host = dns_cache.get(ip) or ""
        rows.append({"ip": ip, "host": host, "port": port, "proc": proc,
                     "n": c, "lan": is_lan(ip)})
    rows.sort(key=lambda r: (r["lan"], r["host"] or r["ip"]))
    return rows

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Packet Monitor</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;
--mgmt:#d29922;--ctrl:#58a6ff;--data:#3fb950;--ext:#a371f7;--out:#f778ba;--in:#79c0ff;--enc:#f85149;--lbl:#7ee787;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 ui-monospace,Menlo,Consolas,monospace}
header{padding:12px 16px;background:var(--panel);border-bottom:1px solid var(--line);
display:flex;flex-wrap:wrap;gap:12px 20px;align-items:center;position:sticky;top:0;z-index:5}
h1{font-size:16px;margin:0;font-weight:600}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--dim);margin-right:6px}
.dot.on{background:var(--data);box-shadow:0 0 6px var(--data)}
.stat{color:var(--dim)}.stat b{color:var(--fg)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{padding:2px 8px;border-radius:10px;font-size:12px;border:1px solid var(--line);cursor:pointer;user-select:none}
.chip.off{opacity:.35}
.chip.MGMT{color:var(--mgmt)}.chip.CTRL{color:var(--ctrl)}.chip.DATA{color:var(--data)}.chip.EXT{color:var(--ext)}
.controls{margin-left:auto;display:flex;gap:8px;align-items:center}
input[type=text]{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:5px 8px;border-radius:6px;width:150px}
button{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:6px;cursor:pointer}
button:hover{border-color:var(--fg)}button.active{background:var(--ctrl);color:#0d1117;border-color:var(--ctrl)}
.wrap{display:flex;align-items:flex-start}
.left{flex:1;min-width:0}.right{width:360px;border-left:1px solid var(--line);position:sticky;top:57px;max-height:calc(100vh - 57px);overflow:auto}
.right h2{font-size:13px;margin:0;padding:10px 14px;color:var(--dim);border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:5px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:57px;background:var(--panel);color:var(--dim);font-weight:600;z-index:4}
.right th{top:35px}
tbody tr:hover{background:#1c2431}
td.cls{font-weight:600}
.MGMT{color:var(--mgmt)}.CTRL{color:var(--ctrl)}.DATA{color:var(--data)}.EXT{color:var(--ext)}
.dir-OUT{color:var(--out)}.dir-IN{color:var(--in)}
.enc{color:var(--enc);font-weight:600}.clear{color:var(--dim)}
.mac{color:var(--fg)}.lbl{color:var(--lbl)}.role{color:var(--dim)}
.detail{background:#10151d;color:var(--dim);white-space:normal}.detail b{color:var(--fg)}
.flag{display:inline-block;background:#21262d;border-radius:4px;padding:1px 6px;margin:0 4px 4px 0;font-size:12px}
tr.frow{cursor:pointer}
.hint{color:var(--dim);font-size:12px;padding:8px 16px}
.host{color:var(--lbl)}.ip{color:var(--dim)}.proc{color:var(--ctrl)}
.note{color:var(--dim);font-size:11px;padding:6px 14px}
.cat{font-weight:600;font-size:12px}
.cat.video{color:var(--enc)}.cat.audio{color:var(--lbl)}.cat.web{color:var(--dim)}
.cat.videob{color:#ffa657}.cat.audiob{color:#79c0ff}
.rate{color:var(--data);text-align:right}.rateup{color:var(--out);text-align:right}
.bar{height:4px;background:var(--enc);border-radius:2px;margin-top:3px}
</style></head><body>
<header>
  <h1>ESP32 Packet Monitor</h1>
  <span><span id="dot" class="dot"></span><span id="conn" class="stat">connecting…</span></span>
  <span class="stat">total <b id="total">0</b></span>
  <span class="stat"><b id="rate">0</b>/s</span>
  <div class="chips" id="chips">
    <span class="chip MGMT" data-c="MGMT">MGMT <b id="c-MGMT">0</b></span>
    <span class="chip CTRL" data-c="CTRL">CTRL <b id="c-CTRL">0</b></span>
    <span class="chip DATA" data-c="DATA">DATA <b id="c-DATA">0</b></span>
    <span class="chip EXT"  data-c="EXT">EXT <b id="c-EXT">0</b></span>
  </div>
  <div class="controls">
    <input id="filter" type="text" placeholder="filter MAC / subtype">
    <button id="pause">Pause</button><button id="clear">Clear</button>
  </div>
</header>
<div class="hint" id="info"></div>
<div class="wrap">
 <div class="left">
  <table><thead><tr><th>#</th><th>time</th><th>dir</th><th>class</th><th>subtype</th>
   <th>from</th><th>to (destination)</th><th>bytes</th><th>rssi</th><th>enc</th></tr></thead>
   <tbody id="rows"></tbody></table>
 </div>
 <div class="right">
   <h2>Where it actually goes — live flows (both directions)</h2>
   <div class="note">Real destination names come from the TLS handshake (SNI), in the clear. Category is guessed from the host and bitrate. The media itself stays encrypted — this is traffic analysis, not decryption.</div>
   <table><thead><tr><th>category</th><th>destination</th><th>&#8595; down</th><th>&#8593; up</th></tr></thead>
   <tbody id="flows"></tbody></table>
 </div>
</div>
<script>
const MAX=600;
let paused=false,total=0,counts={MGMT:0,CTRL:0,DATA:0,EXT:0},
    show={MGMT:1,CTRL:1,DATA:1,EXT:1},filt="",win=[];
const $=id=>document.getElementById(id);
function addr(a){if(!a)return '<span class="role">-</span>';
  return `<span class="mac">${a.mac}</span>`+(a.label?` <span class="lbl">${a.label}</span>`:"");}
function detail(f){
  let s=f.addrs.map(a=>`<b>${a.mac}</b> ${a.role}${a.label?' — '+a.label:''}`).join(" &nbsp; ");
  let fl=(f.flags||[]).map(x=>`<span class="flag">${x}</span>`).join("");
  if(f.seq!==undefined) fl+=`<span class="flag">seq ${f.seq}/frag ${f.frag}</span>`;
  if(f.tid!==undefined) fl+=`<span class="flag">QoS TID ${f.tid}</span>`;
  fl+=`<span class="flag">${f.prot?"WPA2 payload encrypted":"no payload / not encrypted"}</span>`;
  return `${s}<br>${fl}`;
}
function addRow(f){
  const tb=$("rows"),tr=document.createElement("tr");tr.className="frow";
  tr.innerHTML=`<td>${f.n}</td><td>${f.t.toFixed(3)}</td>
    <td class="dir-${f.dir}">${f.dir}</td><td class="cls ${f.cls}">${f.cls}</td><td>${f.sub}</td>
    <td>${addr(f.src)}</td><td>${addr(f.dst)}</td>
    <td>${f.len}</td><td>${f.rssi}</td>
    <td class="${f.prot?'enc':'clear'}">${f.prot?'enc':'—'}</td>`;
  tr.onclick=()=>{
    if(tr.nextSibling&&tr.nextSibling.classList&&tr.nextSibling.classList.contains('detail-row')){tr.nextSibling.remove();return;}
    const d=document.createElement('tr');d.className='detail-row';
    d.innerHTML=`<td></td><td colspan="9" class="detail">${detail(f)}</td>`;tr.after(d);};
  const cls=f.cls,txt=tr.textContent.toLowerCase();
  if(!(show[cls]&&(!filt||txt.includes(filt)))) tr.style.display="none";
  tb.prepend(tr);while(tb.children.length>MAX) tb.lastChild.remove();
}
const es=new EventSource("/stream");
es.onmessage=e=>{const m=JSON.parse(e.data);
  if(m.ev==="frame"){const f=m.f;total++;counts[f.cls]=(counts[f.cls]||0)+1;
    $("total").textContent=total;$("c-"+f.cls).textContent=counts[f.cls];
    win.push(Date.now());if(!paused) addRow(f);}
  else if(m.ev==="note"){$("info").textContent=m.text;}};
es.onopen=()=>{$("dot").classList.add("on");$("conn").textContent="serial connected";};
es.onerror=()=>{$("dot").classList.remove("on");$("conn").textContent="stream lost, retrying…";};
setInterval(()=>{const cut=Date.now()-1000;win=win.filter(t=>t>=cut);$("rate").textContent=win.length;},500);
$("pause").onclick=e=>{paused=!paused;e.target.textContent=paused?"Resume":"Pause";e.target.classList.toggle("active",paused);};
$("clear").onclick=()=>{$("rows").innerHTML="";};
$("filter").oninput=e=>{filt=e.target.value.toLowerCase();document.querySelectorAll('tr.detail-row').forEach(r=>r.remove());refilter();};
$("chips").onclick=e=>{const c=e.target.closest('.chip');if(!c)return;const k=c.dataset.c;show[k]=!show[k];c.classList.toggle('off',!show[k]);refilter();};
function refilter(){$("rows").querySelectorAll('tr.frow').forEach(tr=>{
  const cls=tr.querySelector('.cls').textContent,txt=tr.textContent.toLowerCase();
  tr.style.display=(show[cls]&&(!filt||txt.includes(filt)))?"":"none";});}
function kbps(v){return v>=1000?(v/1000).toFixed(1)+" Mbps":v.toFixed(0)+" kbps";}
function catClass(c){if(c=="video")return"video";if(c=="audio")return"audio";
  if(c.startsWith("video"))return"videob";if(c.startsWith("audio"))return"audiob";return"web";}
let peak=1;
async function loadFlows(){try{const r=await fetch('/flows');const rows=await r.json();
  peak=Math.max(peak*0.9,...rows.map(x=>x.down_kbps),1);
  $("flows").innerHTML=rows.map(c=>{
    const name=c.host?`<span class="host">${c.host}</span>`:`<span class="ip">${c.ip}</span>`;
    const w=Math.min(100,100*c.down_kbps/peak);
    const bar=c.down_kbps>1?`<div class="bar" style="width:${w}%"></div>`:"";
    return `<tr><td class="cat ${catClass(c.cat)}">${c.cat}</td>
      <td>${name} <span class="role">${c.conns>1?c.conns+" conns":""}</span>${bar}</td>
      <td class="rate">${c.down_kbps>1?kbps(c.down_kbps):"·"}</td>
      <td class="rateup">${c.up_kbps>1?kbps(c.up_kbps):"·"}</td></tr>`;}).join('');
  }catch(e){}}
loadFlows();setInterval(loadFlows,1000);
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        elif self.path == "/conns":
            self._json(conns())
        elif self.path == "/flows":
            self._json(flowcap.snapshot())
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            q = queue.Queue(maxsize=2000)
            with subs_lock: subs.append(q)
            try:
                self.wfile.write(b": connected\n\n")
                while True:
                    try:
                        data = q.get(timeout=15)
                        self.wfile.write(("data: %s\n\n" % data).encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with subs_lock:
                    if q in subs: subs.remove(q)
        else:
            self.send_error(404)

def main():
    build_labels()
    try:
        flowcap.start()
    except Exception as e:
        print('flow capture disabled (need root):', e)
    threading.Thread(target=reader, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print("ESP32 packet monitor on http://localhost:%d   reading %s" % (PORT, DEV))
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\nstopped")

if __name__ == "__main__":
    main()
