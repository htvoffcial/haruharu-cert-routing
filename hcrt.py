#!/usr/bin/env python3
"""Haruharu Cert Routing (HCRT) v1

同一ホスト名・同一ポートのまま、URL パスによって提示する TLS 証明書を
切り替える実験的 HTTPS サーバ。TLS 1.3 を自前実装し、証明書の選択を
「接続」ではなく「パス」に結びつけるための3つの機構を持つ:

  1. ChronoCert 巻き戻し (HTTP/2): セッション・チケットに系列IDを刻み、
     パスと証明書が一致しないナビゲーションへ RST_STREAM(REFUSED_STREAM)
     + GOAWAY を返してブラウザの透過リトライを誘導し、再接続で目標
     ルートの証明書を提示する。
  2. 0-RTT 覗き見 (HTTP/1.1): 再開接続の early data を復号してパスを読み、
     PSK を拒否して目標ルートの証明書でフルハンドシェイクする
     (early data を送るクライアントでのみ有効。Chrome は送らない)。
  3. 同一IPフォールバック: チケットを提示しないクライアント (Safari) 向けに、
     巻き戻し直後の同一リモートIPからの再接続を短時間だけ同一系列とみなす。

設定は config.hcrt (書式は README / config.example.hcrt 参照)。
対応範囲 (v1): TLS 1.3 のみ / TLS_AES_128_GCM_SHA256 のみ /
鍵交換 X25519 のみ / 証明書は ECDSA P-256 のみ / 配信は静的ファイルのみ。
"""
import hashlib, hmac as hmac_mod, os, socket, struct, sys, threading, time
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

SUITE = 0x1301  # TLS_AES_128_GCM_SHA256
GROUP_X25519 = 0x001D
SIG_ECDSA256 = 0x0403

# ============================================================
#  設定 (config.hcrt)
# ============================================================
class ConfigError(Exception):
    pass

class CertBundle:
    """証明書チェーン + 秘密鍵。ファイル更新を検知してホットリロードする。"""
    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path = key_path
        self.lock = threading.Lock()
        self._load()
        self.mtimes = self._mtimes()
    def _mtimes(self):
        return (os.path.getmtime(self.cert_path), os.path.getmtime(self.key_path))
    def _load(self):
        key = serialization.load_pem_private_key(open(self.key_path, "rb").read(), None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ConfigError(f"{self.key_path}: v1 は ECDSA P-256 の鍵のみ対応です")
        certs = x509.load_pem_x509_certificates(open(self.cert_path, "rb").read())
        if not certs:
            raise ConfigError(f"{self.cert_path}: 証明書が読めません")
        self.key = key
        self.ders = [c.public_bytes(serialization.Encoding.DER) for c in certs]
        self.serial = format(certs[0].serial_number, "X")
        self.issuer = certs[0].issuer.rfc4514_string()
        self.subject = certs[0].subject.rfc4514_string()
        self.fingerprint = hashlib.sha256(self.ders[0]).hexdigest()
    def reload_if_changed(self):
        try:
            mt = self._mtimes()
            if mt != self.mtimes:
                with self.lock:
                    self._load()
                self.mtimes = mt
                print(f"[hcrt] cert reloaded: {self.cert_path} (serial {self.serial[:16]}…)", flush=True)
        except Exception as e:
            print(f"[hcrt] cert reload failed ({self.cert_path}): {e}", flush=True)

class Route:
    def __init__(self, prefix, bundle, root):
        self.prefix = prefix                    # 例: "/a/*"
        self.static_part = prefix[:-2] if prefix.endswith("/*") else prefix
        self.bundle = bundle
        self.root = root                        # 静的ファイルのルート (絶対パス)
    def match(self, path):
        sp = self.static_part
        if sp == "":                            # "/*" は全マッチ
            return True
        return path == sp or path.startswith(sp + "/")
    def inner_path(self, path):
        rest = path[len(self.static_part):]
        return rest if rest else "/"

class HostConfig:
    def __init__(self, name):
        self.name = name
        self.default_bundle = None
        self.routes = []                        # 定義順 → 照合は static_part 長い順
    def match_route(self, path):
        best = None
        for r in self.routes:
            if r.match(path) and (best is None or len(r.static_part) > len(best.static_part)):
                best = r
        return best

class Config:
    def __init__(self):
        self.listen_addr = "::"
        self.listen_port = 443
        self.hosts = {}                         # name -> HostConfig (挿入順保持)
        self.bundles = {}                       # (cert, key) -> CertBundle

    def bundle(self, cert_path, key_path):
        k = (cert_path, key_path)
        if k not in self.bundles:
            self.bundles[k] = CertBundle(cert_path, key_path)
        return self.bundles[k]

    def host_for_sni(self, sni):
        if sni and sni in self.hosts:
            return self.hosts[sni]
        return next(iter(self.hosts.values()))  # 既定は先頭の host

def load_config(path):
    base = os.path.dirname(os.path.abspath(path))
    cfg = Config()
    lines = []
    for raw in open(path, encoding="utf-8"):
        line = raw.split("#", 1)[0].strip()
        if line: lines.append(line)
    cur = None
    def absp(p):
        return p if os.path.isabs(p) else os.path.join(base, p)
    for line in lines:
        toks = line.split()
        if toks[0] == "listen" and len(toks) == 2:
            v = toks[1]
            if v.startswith("[") and "]:" in v:
                cfg.listen_addr = v[1:v.index("]")]
                cfg.listen_port = int(v[v.index("]:") + 2:])
            elif ":" in v:
                cfg.listen_addr, p = v.rsplit(":", 1)
                cfg.listen_port = int(p)
            else:
                cfg.listen_port = int(v)
        elif toks[0] == "host" and len(toks) >= 2:
            cur = HostConfig(toks[1])
            cfg.hosts[cur.name] = cur
        elif toks[0] == "}" :
            cur = None
        elif cur is not None and toks[0] == "default" and len(toks) == 3:
            cur.default_bundle = cfg.bundle(absp(toks[1]), absp(toks[2]))
        elif cur is not None and toks[0] == "route":
            # route <prefix> <cert> <key> root <dir>
            if len(toks) != 6 or toks[4] != "root":
                raise ConfigError(f"route 行の書式が違います: {line}")
            bundle = cfg.bundle(absp(toks[2]), absp(toks[3]))
            cur.routes.append(Route(toks[1], bundle, absp(toks[5])))
        elif line in ("{",):
            continue
        else:
            raise ConfigError(f"解釈できない行: {line}")
    if not cfg.hosts:
        raise ConfigError("host が1つも定義されていません")
    for h in cfg.hosts.values():
        if h.default_bundle is None:
            raise ConfigError(f"host {h.name}: default 証明書がありません")
        for r in h.routes:
            if not os.path.isdir(r.root):
                raise ConfigError(f"host {h.name} route {r.prefix}: root {r.root} がありません")
    return cfg

# ============================================================
#  チケット / 巻き戻し記録
# ============================================================
PENDING = {}          # lineage hex -> (route_index_key, epoch)  ※値は (bundle_fingerprint, epoch)
PENDING_IP = {}       # remote ip -> (bundle_fingerprint, epoch)
PENDING_LOCK = threading.Lock()
PENDING_TTL = 30.0
PENDING_IP_TTL = 10.0

def pending_set(lineage_hex, fingerprint, ip=None):
    with PENDING_LOCK:
        PENDING[lineage_hex] = (fingerprint, time.time())
        if ip: PENDING_IP[ip] = (fingerprint, time.time())

def pending_pop_lineage(lineage_hex):
    with PENDING_LOCK:
        ent = PENDING.pop(lineage_hex, None)
    return ent[0] if ent and time.time() - ent[1] <= PENDING_TTL else None

def pending_pop_ip(ip):
    with PENDING_LOCK:
        ent = PENDING_IP.pop(ip, None)
    return ent[0] if ent and time.time() - ent[1] <= PENDING_IP_TTL else None

TICKET_KEY_PATH = os.environ.get("HCRT_TICKET_KEY", "")
def load_ticket_key(cfg_dir):
    global TICKET_KEY
    p = TICKET_KEY_PATH or os.path.join(cfg_dir, ".hcrt-ticket-key.bin")
    if os.path.exists(p):
        TICKET_KEY = open(p, "rb").read()
    else:
        TICKET_KEY = os.urandom(32)
        open(p, "wb").write(TICKET_KEY); os.chmod(p, 0o600)
    return p

def make_ticket(res_master: bytes, ticket_nonce: bytes, lineage: bytes) -> bytes:
    # 中身: lineage(8) || resumption_master_secret(32) || nonce長(1) || ticket_nonce || 有効期限(8)
    nonce = os.urandom(12)
    pt = (lineage + res_master + bytes([len(ticket_nonce)]) + ticket_nonce
          + struct.pack(">Q", int(time.time()) + 86400))
    return nonce + AESGCM(TICKET_KEY).encrypt(nonce, pt, None)

def open_ticket(blob: bytes):
    """(psk, lineage) を返す。期限切れ・改竄は None。"""
    try:
        pt = AESGCM(TICKET_KEY).decrypt(blob[:12], blob[12:], None)
        lineage = pt[:8]
        res_master = pt[8:40]
        nl = pt[40]
        ticket_nonce = pt[41:41 + nl]
        expiry = struct.unpack(">Q", pt[41 + nl:49 + nl])[0]
        if expiry < int(time.time()): return None
        return expand_label(res_master, b"resumption", ticket_nonce, 32), lineage
    except Exception:
        return None

# ============================================================
#  HKDF (RFC 8446)
# ============================================================
def hkdf_extract(salt, ikm):
    return hmac_mod.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]
def expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)
def derive_secret(secret, label, msg_hash):
    return expand_label(secret, label, msg_hash, 32)
def traffic_keys(secret):
    return expand_label(secret, b"key", b"", 16), expand_label(secret, b"iv", b"", 12)

def aead_encrypt(key, iv, seq, header, plaintext):
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    return AESGCM(key).encrypt(nonce, plaintext, header)
def aead_decrypt(key, iv, seq, header, ciphertext):
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    return AESGCM(key).decrypt(nonce, ciphertext, header)

# ============================================================
#  レコード層 / ClientHello 解析
# ============================================================
class Conn:
    def __init__(self, sock):
        self.s = sock; self.buf = b""
    def read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk: raise ConnectionError("eof")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out
    def read_record(self):
        hdr = self.read_exact(5)
        ln = struct.unpack(">H", hdr[3:5])[0]
        return hdr, self.read_exact(ln)
    def send_record(self, ctype, payload):
        self.s.sendall(bytes([ctype]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload)
    def send_encrypted(self, key, iv, seq, inner_type, payload):
        inner = payload + bytes([inner_type])
        ct = aead_encrypt(key, iv, seq, b"\x17\x03\x03" + struct.pack(">H", len(inner) + 16), inner)
        self.send_record(23, ct)

def parse_client_hello(msg: bytes) -> dict:
    body = msg[4:]
    p = 0
    p += 2 + 32  # legacy_version + random
    sid_len = body[p]; p += 1 + sid_len
    cs_len = struct.unpack(">H", body[p:p+2])[0]; p += 2
    suites = [struct.unpack(">H", body[i:i+2])[0] for i in range(p, p + cs_len, 2)]; p += cs_len
    comp_len = body[p]; p += 1 + comp_len
    ext_len = struct.unpack(">H", body[p:p+2])[0]; p += 2
    exts = {}
    end = p + ext_len
    while p < end:
        etype, elen = struct.unpack(">HH", body[p:p+4]); p += 4
        exts[etype] = body[p:p+elen]; p += elen
    out = {"suites": suites, "exts": exts}
    p = 34; sid_len = body[p]; out["session_id"] = body[p+1:p+1+sid_len]
    if 0 in exts:  # server_name (SNI)
        try:
            d = exts[0]
            nl = struct.unpack(">H", d[3:5])[0]
            out["sni"] = d[5:5+nl].decode("idna").lower()
        except Exception:
            out["sni"] = None
    else:
        out["sni"] = None
    if 51 in exts:  # key_share
        d = exts[51]; q = 2
        while q < len(d):
            g, kl = struct.unpack(">HH", d[q:q+4]); q += 4
            if g == GROUP_X25519: out["x25519_pub"] = d[q:q+kl]
            q += kl
    if 43 in exts:
        d = exts[43]; out["versions"] = [struct.unpack(">H", d[i:i+2])[0] for i in range(1, len(d), 2)]
    if 16 in exts:
        d = exts[16]; ln = struct.unpack(">H", d[:2])[0]
        protos, q = [], 2
        while q < 2 + ln:
            nl = d[q]; protos.append(d[q+1:q+1+nl]); q += 1 + nl
        out["alpn_list"] = protos
    if 41 in exts:  # pre_shared_key
        d = exts[41]
        id_len = struct.unpack(">H", d[:2])[0]
        q = 2; identities = []
        while q < 2 + id_len:
            il = struct.unpack(">H", d[q:q+2])[0]; q += 2
            identities.append(d[q:q+il]); q += il + 4
        out["psk_identity"] = identities[0] if identities else None
    out["early_data_offered"] = 42 in exts
    return out

def ext(etype, data):
    return struct.pack(">HH", etype, len(data)) + data
def hs_msg(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body

# ============================================================
#  アプリケーション層 IO
# ============================================================
class AppIO:
    """クライアント app 鍵での復号読み取りと、サーバ app 鍵での暗号化送信。
    KeyUpdate は透過的に処理する。"""
    def __init__(self, conn, c_secret, s_key, s_iv, s_seq):
        self.c = conn
        self.c_secret = c_secret
        self.ck, self.civ = traffic_keys(c_secret)
        self.cseq = 0
        self.sk, self.siv, self.sseq = s_key, s_iv, s_seq
    def read_msg(self):
        while True:
            hdr, payload = self.c.read_record()
            if hdr[0] == 20: continue  # dummy CCS
            pt = aead_decrypt(self.ck, self.civ, self.cseq, hdr, payload); self.cseq += 1
            inner = pt.rstrip(b"\x00"); itype = inner[-1]; content = inner[:-1]
            if itype == 21: raise ConnectionError("alert")
            if itype == 22 and content and content[0] == 24:  # KeyUpdate
                self.c_secret = expand_label(self.c_secret, b"ku", b"", 32)
                self.ck, self.civ = traffic_keys(self.c_secret)
                continue
            return itype, content
    def send_app(self, data: bytes):
        for i in range(0, len(data), 16000):
            self.c.send_encrypted(self.sk, self.siv, self.sseq, 23, data[i:i+16000])
            self.sseq += 1

# ============================================================
#  静的ファイル配信
# ============================================================
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript",
    ".json": "application/json", ".txt": "text/plain; charset=utf-8",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon",
    ".webp": "image/webp", ".woff": "font/woff", ".woff2": "font/woff2",
    ".xml": "application/xml", ".pdf": "application/pdf",
}

def substitute_placeholders(data: bytes, bundle, how, route_prefix, host_name) -> bytes:
    """HTML 内の %%HCRT_*%% を、この接続で実際に提示した証明書の情報で置換する。"""
    if b"%%HCRT_" not in data: return data
    text = data.decode("utf-8")
    text = (text.replace("%%HCRT_CERT_SERIAL%%", bundle.serial)
                .replace("%%HCRT_CERT_ISSUER%%", bundle.issuer)
                .replace("%%HCRT_CERT_SUBJECT%%", bundle.subject)
                .replace("%%HCRT_CERT_FINGERPRINT%%", bundle.fingerprint)
                .replace("%%HCRT_HOW%%", how)
                .replace("%%HCRT_ROUTE%%", route_prefix or "-")
                .replace("%%HCRT_HOST%%", host_name))
    return text.encode("utf-8")

def serve_static(route, path, bundle, how, host_name):
    """(status, content_type, body) を返す。"""
    inner = route.inner_path(path)
    root = os.path.realpath(route.root)
    rel = inner.lstrip("/")
    target = os.path.realpath(os.path.join(root, rel))
    if target != root and not target.startswith(root + os.sep):
        return 403, "text/plain; charset=utf-8", "403 Forbidden".encode()
    if os.path.isdir(target):
        target = os.path.join(target, "index.html")
    elif not os.path.exists(target) and os.path.exists(target + ".html"):
        target = target + ".html"
    if not os.path.isfile(target):
        return 404, "text/html; charset=utf-8", not_found_page(path, bundle, how, route, host_name)
    ctype = CONTENT_TYPES.get(os.path.splitext(target)[1].lower(), "application/octet-stream")
    with open(target, "rb") as f:
        data = f.read()
    if ctype.startswith("text/html"):
        data = substitute_placeholders(data, bundle, how, route.prefix, host_name)
    return 200, ctype, data

def not_found_page(path, bundle, how, route, host_name):
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>404 Not Found</title></head><body>
<h1>404 Not Found</h1><p>{path}</p>
<p>配信証明書シリアル: {bundle.serial} / 発行者: {bundle.issuer}</p>
</body></html>"""
    return html.encode()

# ============================================================
#  HTTP/2 (ChronoCert 巻き戻し + 静的配信)
# ============================================================
def run_h2(appio, addr, host, bound_bundle, lineage_hex, how):
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import RequestReceived, DataReceived, StreamEnded, ConnectionTerminated
    from h2.errors import ErrorCodes
    config = H2Configuration(client_side=False, header_encoding=None)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    state = {"last_processed": 0, "requests": {}, "done": set()}

    def flush():
        data = conn.data_to_send()
        if data: appio.send_app(data)

    def process(stream_id, headers):
        if stream_id in state["done"]: return
        state["done"].add(stream_id)
        state["requests"].pop(stream_id, None)
        method = headers.get(":method", "GET")
        path = headers.get(":path", "/").split("?")[0]
        route = host.match_route(path)
        sfm = headers.get("sec-fetch-mode"); sfd = headers.get("sec-fetch-dest")
        is_nav = (sfm == "navigate") or (sfd == "document") or (sfm is None and route is not None)
        if is_nav and route is not None and route.bundle.fingerprint != bound_bundle.fingerprint:
            pending_set(lineage_hex, route.bundle.fingerprint, ip=addr[0])
            print(f"[{addr}] REWIND: bound_fp={bound_bundle.fingerprint[:8]}… "
                  f"requested route={route.prefix} -> RST_STREAM(REFUSED) + GOAWAY", flush=True)
            conn.reset_stream(stream_id, error_code=ErrorCodes.REFUSED_STREAM)
            flush()
            conn.close_connection(error_code=ErrorCodes.NO_ERROR,
                                  last_stream_id=state["last_processed"])
            flush()
            time.sleep(0.25)
            raise ConnectionError("rewound")
        if method not in ("GET", "HEAD"):
            status, ctype, body = 405, "text/plain; charset=utf-8", b"405 Method Not Allowed"
        elif route is None:
            status, ctype, body = 404, "text/html; charset=utf-8", \
                not_found_page(path, bound_bundle, how, None, host.name)
        else:
            status, ctype, body = serve_static(route, path, bound_bundle, how, host.name)
        print(f"[{addr}] H2 {method} {path} -> {status} (cert serial {bound_bundle.serial[:12]}…)", flush=True)
        conn.send_headers(stream_id, [(b":status", str(status).encode()),
                                      (b"content-type", ctype.encode()),
                                      (b"cache-control", b"no-store"),
                                      (b"content-length", str(len(body)).encode())])
        if method != "HEAD" and body:
            conn.send_data(stream_id, body, end_stream=True)
        else:
            conn.end_stream(stream_id)
        state["last_processed"] = max(state["last_processed"], stream_id)
        flush()

    flush()
    while True:
        itype, content = appio.read_msg()
        if itype != 23: continue
        events = conn.receive_data(content)
        for ev in events:
            if isinstance(ev, RequestReceived):
                hdrs = {}
                for k, v in ev.headers:
                    hdrs[k.decode("latin1")] = v.decode("latin1")
                state["requests"][ev.stream_id] = hdrs
                if ev.stream_ended: process(ev.stream_id, hdrs)
            elif isinstance(ev, DataReceived):
                if ev.flow_controlled_length:
                    conn.increase_flow_control_window(1073741823, ev.stream_id)
                if ev.stream_ended and ev.stream_id in state["requests"]:
                    process(ev.stream_id, state["requests"][ev.stream_id])
            elif isinstance(ev, StreamEnded):
                if ev.stream_id in state["requests"]:
                    process(ev.stream_id, state["requests"][ev.stream_id])
            elif isinstance(ev, ConnectionTerminated):
                raise ConnectionError("goaway received")
        flush()

def run_h2_with_prefix(appio, prefix, addr, host, bound_bundle, lineage_hex, how):
    if not prefix:
        return run_h2(appio, addr, host, bound_bundle, lineage_hex, how)
    orig_read = appio.read_msg
    stash = [(23, prefix)]
    def read_msg2():
        if stash: return stash.pop(0)
        return orig_read()
    appio.read_msg = read_msg2
    try:
        run_h2(appio, addr, host, bound_bundle, lineage_hex, how)
    finally:
        appio.read_msg = orig_read

# ============================================================
#  接続処理
# ============================================================
def handle(sock, addr, cfg):
    c = Conn(sock)
    try:
        # --- ClientHello ---
        hsbuf = b""
        while len(hsbuf) < 4 or len(hsbuf) < 4 + int.from_bytes(hsbuf[1:4], "big"):
            hdr, payload = c.read_record()
            if hdr[0] == 22: hsbuf += payload
        ch_msg = hsbuf[:4 + int.from_bytes(hsbuf[1:4], "big")]
        ch = parse_client_hello(ch_msg)
        if 0x0304 not in ch.get("versions", []) or SUITE not in ch["suites"] or "x25519_pub" not in ch:
            print(f"[{addr}] unsupported ClientHello", flush=True); return
        host = cfg.host_for_sni(ch.get("sni"))
        bundles_by_fp = {host.default_bundle.fingerprint: host.default_bundle}
        for r in host.routes:
            bundles_by_fp[r.bundle.fingerprint] = r.bundle

        # --- チケット解決 (系列の引き継ぎ) ---
        opened = open_ticket(ch["psk_identity"]) if ch.get("psk_identity") else None
        psk = opened[0] if opened else None
        lineage = opened[1] if opened else os.urandom(8)
        lineage_hex = lineage.hex()

        # --- early data 覗き見 (0-RTT 方式) ---
        peeked_path = None
        if psk and ch["early_data_offered"]:
            early_secret = hkdf_extract(b"\x00" * 32, psk)
            cet = derive_secret(early_secret, b"c e traffic", hashlib.sha256(ch_msg).digest())
            ek, eiv = traffic_keys(cet)
            seq, data = 0, b""
            sock.settimeout(1.2)
            try:
                while b"\r\n\r\n" not in data:
                    hdr, payload = c.read_record()
                    if hdr[0] == 20: continue
                    if hdr[0] != 23: break
                    pt = aead_decrypt(ek, eiv, seq, hdr, payload); seq += 1
                    inner_type = pt.rstrip(b"\x00")[-1]
                    if inner_type == 23: data += pt.rstrip(b"\x00")[:-1]
            except Exception as e:
                print(f"[{addr}] early data read note: {e}", flush=True)
            finally:
                sock.settimeout(None)
            if data:
                parts = data.split(b"\r\n", 1)[0].decode("latin1").split(" ")
                if len(parts) >= 2: peeked_path = parts[1]
            print(f"[{addr}] PEEKED early data path: {peeked_path}", flush=True)

        # --- 証明書選択: early data > 巻き戻し予定 (系列→IP) > 既定 ---
        how = "既定"
        chosen = host.default_bundle
        if peeked_path:
            r = host.match_route(peeked_path.split("?")[0])
            if r is not None:
                chosen = r.bundle
                how = f"0-RTT early data 覗き見（パス {peeked_path}）"
        else:
            fp = pending_pop_lineage(lineage_hex)
            if fp and fp in bundles_by_fp:
                chosen = bundles_by_fp[fp]
                how = "ChronoCert 巻き戻し（系列ID）"
            elif opened is None:
                fp = pending_pop_ip(addr[0])
                if fp and fp in bundles_by_fp:
                    chosen = bundles_by_fp[fp]
                    how = "ChronoCert 巻き戻し（同一IPフォールバック）"
        print(f"[{addr}] host={host.name} cert serial={chosen.serial[:16]}… how={how} "
              f"psk={'ok' if psk else 'no'} alpn={ch.get('alpn_list')}", flush=True)

        # --- ALPN: h2 優先 ---
        offered = ch.get("alpn_list", [])
        proto = b"h2" if b"h2" in offered else (b"http/1.1" if b"http/1.1" in offered else None)

        # --- ServerHello (PSK は拒否してフルハンドシェイク) ---
        ecdhe_priv = x25519.X25519PrivateKey.generate()
        shared = ecdhe_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ch["x25519_pub"]))
        server_random = os.urandom(32)
        sh_body = (b"\x03\x03" + server_random + bytes([len(ch["session_id"])]) + ch["session_id"]
                   + struct.pack(">H", SUITE) + b"\x00")
        sh_exts = ext(43, b"\x03\x04") + ext(51, struct.pack(">H", GROUP_X25519)
                        + struct.pack(">H", 32) + ecdhe_priv.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        sh_body += struct.pack(">H", len(sh_exts)) + sh_exts
        sh_msg = hs_msg(2, sh_body)
        transcript = hashlib.sha256(ch_msg + sh_msg)
        c.send_record(22, sh_msg)

        early0 = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        derived = derive_secret(early0, b"derived", hashlib.sha256(b"").digest())
        hs_secret = hkdf_extract(derived, shared)
        s_hs = derive_secret(hs_secret, b"s hs traffic", transcript.digest())
        c_hs = derive_secret(hs_secret, b"c hs traffic", transcript.digest())
        sk, siv = traffic_keys(s_hs); ck, civ = traffic_keys(c_hs)
        sseq = 0
        def send_hs(mtype, body):
            nonlocal sseq
            m = hs_msg(mtype, body)
            transcript.update(m)
            c.send_encrypted(sk, siv, sseq, 22, m); sseq += 1
            return m

        ee_exts = b""
        if proto is not None:
            ee_exts += ext(16, struct.pack(">H", 1 + len(proto)) + bytes([len(proto)]) + proto)
        send_hs(8, struct.pack(">H", len(ee_exts)) + ee_exts)
        entries = b""
        for der in chosen.ders:
            entries += len(der).to_bytes(3, "big") + der + struct.pack(">H", 0)
        send_hs(11, b"\x00" + len(entries).to_bytes(3, "big") + entries)
        sig_input = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + transcript.digest()
        sig = chosen.key.sign(sig_input, ec.ECDSA(hashes.SHA256()))
        send_hs(15, struct.pack(">HH", SIG_ECDSA256, len(sig)) + sig)
        fin_key_s = expand_label(s_hs, b"finished", b"", 32)
        verify_s = hmac_mod.new(fin_key_s, transcript.digest(), hashlib.sha256).digest()
        send_hs(20, verify_s)
        hash_after_sfin = transcript.digest()

        # --- クライアント Finished (検証あり) ---
        fin_key_c = expand_label(c_hs, b"finished", b"", 32)
        cseq = 0; got_finished = False; app_buf = b""
        while not got_finished:
            hdr, payload = c.read_record()
            if hdr[0] == 20: continue
            try:
                pt = aead_decrypt(ck, civ, cseq, hdr, payload)
            except Exception:
                continue  # 証明書を拒否して切断するクライアント等のレコードは読み飛ばす
            cseq += 1
            inner = pt.rstrip(b"\x00"); itype = inner[-1]; content = inner[:-1]
            if itype == 22:
                if content[0] == 20:  # Finished
                    expected = hmac_mod.new(fin_key_c, transcript.digest(), hashlib.sha256).digest()
                    if not hmac_mod.compare_digest(expected, content[4:]):
                        raise ConnectionError("client Finished verify failed")
                    got_finished = True
                transcript.update(content)
            elif itype == 23:
                app_buf += content

        # --- アプリケーション鍵 ---
        derived2 = derive_secret(hs_secret, b"derived", hashlib.sha256(b"").digest())
        master = hkdf_extract(derived2, b"\x00" * 32)
        c_ap = derive_secret(master, b"c ap traffic", hash_after_sfin)
        s_ap = derive_secret(master, b"s ap traffic", hash_after_sfin)
        ak_s, aiv_s = traffic_keys(s_ap)

        # NewSessionTicket x2 (early_data 許可 + 系列ID 刻印)
        res_master = derive_secret(master, b"res master", transcript.digest())
        aseq_s = 0
        for _ in range(2):
            age_add = struct.unpack(">I", os.urandom(4))[0]
            ticket_nonce = os.urandom(8)
            ticket = make_ticket(res_master, ticket_nonce, lineage)
            nst_exts = ext(42, struct.pack(">I", 16384))
            nst_body = (struct.pack(">I", 86400) + struct.pack(">I", age_add)
                        + bytes([len(ticket_nonce)]) + ticket_nonce
                        + struct.pack(">H", len(ticket)) + ticket
                        + struct.pack(">H", len(nst_exts)) + nst_exts)
            m = hs_msg(4, nst_body)
            c.send_encrypted(ak_s, aiv_s, aseq_s, 22, m); aseq_s += 1

        appio = AppIO(c, c_ap, ak_s, aiv_s, aseq_s)

        if proto == b"h2":
            run_h2_with_prefix(appio, app_buf, addr, host, chosen, lineage_hex, how)
        else:
            # --- HTTP/1.1 (1リクエストで閉じる) ---
            buf = app_buf
            while b"\r\n\r\n" not in buf:
                itype, content = appio.read_msg()
                if itype == 23: buf += content
            line = buf.split(b"\r\n", 1)[0].decode("latin1")
            parts = line.split(" ")
            method = parts[0] if parts else "GET"
            path = (parts[1] if len(parts) >= 2 else "/").split("?")[0]
            route = host.match_route(path)
            if method not in ("GET", "HEAD"):
                status, ctype, body = 405, "text/plain; charset=utf-8", b"405 Method Not Allowed"
            elif route is None:
                status, ctype, body = 404, "text/html; charset=utf-8", \
                    not_found_page(path, chosen, how, None, host.name)
            else:
                status, ctype, body = serve_static(route, path, chosen, how, host.name)
            print(f"[{addr}] H1 {method} {path} -> {status} (cert serial {chosen.serial[:12]}…)", flush=True)
            resp = (f"HTTP/1.1 {status} {'OK' if status == 200 else 'Error'}\r\n".encode()
                    + b"Content-Type: " + ctype.encode() + b"\r\n"
                    + b"Content-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + (b"" if method == "HEAD" else body))
            appio.send_app(resp)
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"[{addr}] error: {type(e).__name__}: {e}", flush=True)
    finally:
        try: sock.close()
        except Exception: pass

# ============================================================
#  main
# ============================================================
def watcher(cfg):
    while True:
        time.sleep(20)
        for b in cfg.bundles.values():
            b.reload_if_changed()

def main():
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.hcrt"
    cfg = load_config(cfg_path)
    key_path = load_ticket_key(os.path.dirname(os.path.abspath(cfg_path)))
    print(f"[hcrt] config={cfg_path} ticket_key={key_path}", flush=True)
    for name, h in cfg.hosts.items():
        print(f"[hcrt] host {name}: default serial={h.default_bundle.serial[:16]}… "
              f"routes={[r.prefix for r in h.routes]}", flush=True)
    threading.Thread(target=watcher, args=(cfg,), daemon=True).start()
    addr, port = cfg.listen_addr, cfg.listen_port
    if ":" in addr:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError: pass
    else:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port)); srv.listen(50)
    print(f"[hcrt] Haruharu Cert Routing listening on [{addr}]:{port}", flush=True)
    while True:
        s, a = srv.accept()
        threading.Thread(target=handle, args=(s, a, cfg), daemon=True).start()

if __name__ == "__main__":
    main()
