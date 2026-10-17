// ESP32 NodeMCU-32S: join WiFi, then sniff the channel and list every
// 802.11 frame transmitted by the laptop. Payloads are WPA2-encrypted,
// so what we can list is: type, destination, size, RSSI.
#include <WiFi.h>
#include "esp_wifi.h"
#include "secrets.h"

// Laptop WiFi MAC (wlo1). All zeros = show frames from every device.
static const uint8_t TARGET_MAC[6] = {0x1c, 0xce, 0x51, 0x41, 0x61, 0x3c};
#define SHOW_INCOMING 1   // 1 = also list frames sent TO the laptop
#define DUMP_HEX       1   // 1 = also emit "RAW <hex>" of the header for the decoder

struct __attribute__((packed)) Hdr80211 {
  uint16_t fc;
  uint16_t duration;
  uint8_t addr1[6];   // receiver
  uint8_t addr2[6];   // transmitter
  uint8_t addr3[6];
  uint16_t seq;
};

struct Rec {
  uint32_t ms;
  uint8_t type, subtype, dir;   // dir: 0 = OUT (laptop sent), 1 = IN
  uint8_t peer[6];
  uint16_t len;
  int8_t rssi;
  bool prot;
  uint8_t rawlen;
  uint8_t raw[40];
};

static QueueHandle_t q;
static volatile uint32_t totalFrames = 0, laptopFrames = 0, laptopBytes = 0, dropped = 0, ampdu = 0;

static bool macEq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }
static bool targetIsAny() {
  for (int i = 0; i < 6; i++) if (TARGET_MAC[i]) return false;
  return true;
}

static void sniffer(void *buf, wifi_promiscuous_pkt_type_t kind) {
  const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
  const Hdr80211 *h = (const Hdr80211 *)p->payload;
  totalFrames++;
  // Aggregated 802.11n frames (A-MPDU) arrive with no header, so the
  // sender is unknown. Count them so the summary shows they exist.
  if (kind == WIFI_PKT_MISC) { ampdu++; return; }

  uint8_t type = (h->fc >> 2) & 0x3;
  uint8_t subtype = (h->fc >> 4) & 0xF;
  // Control frames CTS(12) and ACK(13) carry no transmitter address.
  if (type == 1 && (subtype == 12 || subtype == 13)) return;

  Rec r;
  bool any = targetIsAny();
  if (any || macEq(h->addr2, TARGET_MAC)) {
    r.dir = 0; memcpy(r.peer, h->addr1, 6);
  } else if (SHOW_INCOMING && macEq(h->addr1, TARGET_MAC)) {
    r.dir = 1; memcpy(r.peer, h->addr2, 6);
  } else {
    return;
  }
  if (!any && r.dir == 0) { laptopFrames++; laptopBytes += p->rx_ctrl.sig_len; }

  r.ms = millis();
  r.type = type; r.subtype = subtype;
  r.len = p->rx_ctrl.sig_len;
  r.rssi = p->rx_ctrl.rssi;
  r.prot = h->fc & 0x4000;
  r.rawlen = p->rx_ctrl.sig_len < 40 ? p->rx_ctrl.sig_len : 40;
  memcpy(r.raw, p->payload, r.rawlen);
  if (xQueueSendFromISR(q, &r, NULL) != pdTRUE) dropped++;
}

static const char *name(uint8_t type, uint8_t st) {
  static const char *mgmt[16] = {"AssocReq","AssocResp","ReassocReq","ReassocResp","ProbeReq","ProbeResp","TimingAdv","Rsvd","Beacon","ATIM","Disassoc","Auth","Deauth","Action","ActionNoAck","Rsvd"};
  static const char *ctrl[16] = {"Rsvd","Rsvd","Trigger","TACK","BeamRpt","VHT-NDP","CtrlExt","CtrlWrap","BlockAckReq","BlockAck","PS-Poll","RTS","CTS","ACK","CF-End","CF-EndAck"};
  static const char *data[16] = {"Data","Data+CFAck","Data+CFPoll","Data+CFAckPoll","Null","CFAck","CFPoll","CFAckPoll","QoS-Data","QoS-Data+CFAck","QoS-Data+CFPoll","QoS-Data+CFAckPoll","QoS-Null","Rsvd","QoS-CFPoll","QoS-CFAckPoll"};
  switch (type) { case 0: return mgmt[st]; case 1: return ctrl[st]; case 2: return data[st]; default: return "Ext"; }
}

static const char *cls(uint8_t type) { return type == 0 ? "MGMT" : type == 1 ? "CTRL" : type == 2 ? "DATA" : "EXT "; }

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.printf("\n== ESP32 packet lister ==\nTarget MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                TARGET_MAC[0], TARGET_MAC[1], TARGET_MAC[2], TARGET_MAC[3], TARGET_MAC[4], TARGET_MAC[5]);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("Connecting to %s", WIFI_SSID);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print('.'); }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("Connected. IP %s  BSSID %s  channel %d  RSSI %d\n",
                  WiFi.localIP().toString().c_str(), WiFi.BSSIDstr().c_str(), WiFi.channel(), WiFi.RSSI());
  } else {
    Serial.println("WiFi join failed, sniffing channel 1 anyway.");
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  }

  q = xQueueCreate(128, sizeof(Rec));
  wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
  esp_wifi_set_promiscuous_filter(&f);
  wifi_promiscuous_filter_t cf = { .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL };
  esp_wifi_set_promiscuous_ctrl_filter(&cf);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_promiscuous(true);
  Serial.println("Sniffing... (time  dir  class  subtype  peer MAC  bytes  RSSI  enc)");
}

void loop() {
  Rec r;
  while (xQueueReceive(q, &r, 0) == pdTRUE) {
    Serial.printf("%8lu.%03lu  %s  %s  %-14s  -> %02x:%02x:%02x:%02x:%02x:%02x  %4u B  %4d dBm  %s\n",
                  r.ms / 1000, r.ms % 1000, r.dir ? "IN " : "OUT", cls(r.type), name(r.type, r.subtype),
                  r.peer[0], r.peer[1], r.peer[2], r.peer[3], r.peer[4], r.peer[5],
                  r.len, r.rssi, r.prot ? "enc" : "clear");
#if DUMP_HEX
    Serial.print("RAW ");
    for (uint8_t i = 0; i < r.rawlen; i++) Serial.printf("%02x", r.raw[i]);
    Serial.println();
#endif
  }
  static uint32_t last = 0;
  if (millis() - last >= 5000) {
    last = millis();
    Serial.printf("---- 5s summary: laptop frames %lu (%lu bytes) | all frames on channel %lu | aggregated/unknown sender %lu | dropped %lu ----\n",
                  laptopFrames, laptopBytes, totalFrames, ampdu, dropped);
    laptopFrames = laptopBytes = totalFrames = ampdu = dropped = 0;
  }
  delay(1);
}
