//! Haruharu Cert Routing (HCRT) v1 — Rust 版
//!
//! Python 版 `hcrt.py` の移植。同一ホスト名・同一ポートのまま、URL パスに
//! よって提示する TLS 証明書を切り替える実験的 HTTPS サーバ。TLS 1.3 を
//! 自前実装し、証明書の選択を「接続」ではなく「パス」に結びつけるための
//! 3つの機構を持つ:
//!
//!   1. ChronoCert 巻き戻し (HTTP/2): セッション・チケットに系列IDを刻み、
//!      パスと証明書が一致しないナビゲーションへ RST_STREAM(REFUSED_STREAM)
//!      + GOAWAY を返してブラウザの透過リトライを誘導し、再接続で目標
//!      ルートの証明書を提示する。
//!   2. 0-RTT 覗き見 (HTTP/1.1): 再開接続の early data を復号してパスを読み、
//!      PSK を拒否して目標ルートの証明書でフルハンドシェイクする。
//!   3. 同一IPフォールバック: チケットを提示しないクライアント向けに、
//!      巻き戻し直後の同一リモートIPからの再接続を短時間だけ同一系列とみなす。
//!
//! 対応範囲 (v1): TLS 1.3 のみ / TLS_AES_128_GCM_SHA256 のみ /
//! 鍵交換 X25519 のみ / 証明書は ECDSA P-256 のみ / 配信は静的ファイルのみ。
//!
//! TLS のレコード層・ハンドシェイク・鍵スケジュール・チケット・巻き戻しは
//! すべて自前実装。crates は暗号プリミティブ (AES-GCM / X25519 / ECDSA /
//! SHA-256 / HMAC) のみに使う (Python 版における `cryptography` と同じ役割)。

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use p256::ecdsa::signature::Signer;

mod huffman_table;

const SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256
const GROUP_X25519: u16 = 0x001D;
const SIG_ECDSA256: u16 = 0x0403;

type Res<T> = Result<T, Box<dyn std::error::Error>>;
type HmacSha256 = Hmac<Sha256>;

fn err<T>(msg: &str) -> Res<T> {
    Err(msg.to_string().into())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

// ============================================================
//  最小 DER リーダ (証明書・秘密鍵のフィールド抽出用)
// ============================================================
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Der { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    /// (タグ, 中身) を1つ読む。
    fn read_tlv(&mut self) -> Res<(u8, &'a [u8])> {
        if self.pos + 2 > self.buf.len() {
            return err("DER: truncated");
        }
        let tag = self.buf[self.pos];
        self.pos += 1;
        let b = self.buf[self.pos];
        self.pos += 1;
        let len: usize = if b & 0x80 == 0 {
            b as usize
        } else {
            let n = (b & 0x7f) as usize;
            if n == 0 || n > 4 || self.pos + n > self.buf.len() {
                return err("DER: bad length");
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | self.buf[self.pos + i] as usize;
            }
            self.pos += n;
            l
        };
        if self.pos + len > self.buf.len() {
            return err("DER: overlong");
        }
        let content = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }
    fn expect(&mut self, tag: u8) -> Res<&'a [u8]> {
        let (t, c) = self.read_tlv()?;
        if t != tag {
            return err("DER: unexpected tag");
        }
        Ok(c)
    }
    fn seq(&mut self) -> Res<Der<'a>> {
        Ok(Der::new(self.expect(0x30)?))
    }
}

// ============================================================
//  PEM / 証明書 / 秘密鍵
// ============================================================
fn pem_blocks(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut cur_type: Option<String> = None;
    let mut cur_b64 = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            cur_type = Some(rest.trim_end_matches('-').to_string());
            cur_b64.clear();
        } else if line.starts_with("-----END ") {
            if let Some(t) = cur_type.take() {
                let cleaned: String = cur_b64.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(der) = B64.decode(cleaned.as_bytes()) {
                    out.push((t, der));
                }
            }
        } else if cur_type.is_some() {
            cur_b64.push_str(line);
        }
    }
    out
}

fn oid_string(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let mut parts = vec![(content[0] / 40) as u64, (content[0] % 40) as u64];
    let mut val: u64 = 0;
    for &b in &content[1..] {
        val = (val << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(val);
            val = 0;
        }
    }
    parts
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn oid_rfc4514_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".into(),
        "2.5.4.4" => "GN".into(),
        "2.5.4.5" => "serialNumber".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.9" => "STREET".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.12" => "title".into(),
        "2.5.4.17" => "postalCode".into(),
        "2.5.4.42" => "GN".into(),
        "0.9.2342.19200300.100.1.25" => "DC".into(),
        "0.9.2342.19200300.100.1.1" => "UID".into(),
        "1.2.840.113549.1.9.1" => "emailAddress".into(),
        _ => oid.to_string(),
    }
}

fn der_string_value(tag: u8, content: &[u8]) -> String {
    match tag {
        0x0c => String::from_utf8_lossy(content).into_owned(), // UTF8String
        0x13 | 0x16 | 0x14 | 0x15 | 0x1a => {
            // PrintableString / IA5String / TeletexString 等は latin-1 近似
            content.iter().map(|&b| b as char).collect()
        }
        0x1e => {
            // BMPString (UTF-16BE)
            let units: Vec<u16> = content
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => content.iter().map(|&b| b as char).collect(),
    }
}

fn rfc4514_escape(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let first = i == 0;
        let last = i == chars.len() - 1;
        if (c as u32) < 0x20 {
            out.push_str(&format!("\\{:02X}", c as u32));
        } else if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (first && (c == '#' || c == ' '))
            || (last && c == ' ')
        {
            out.push('\\');
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// X.501 Name の中身 (RDNSequence のコンテンツ) を RFC4514 文字列にする。
/// Python `cryptography` の rfc4514_string() と同じく RDN を逆順に並べる。
fn name_rfc4514(content: &[u8]) -> Res<String> {
    let mut rdns: Vec<Vec<(String, String)>> = Vec::new();
    let mut top = Der::new(content);
    while !top.is_empty() {
        let set_content = top.expect(0x31)?;
        let mut set = Der::new(set_content);
        let mut rdn = Vec::new();
        while !set.is_empty() {
            let atv = set.seq()?;
            let mut atv = atv;
            let oid_c = atv.expect(0x06)?;
            let (vtag, vcontent) = atv.read_tlv()?;
            rdn.push((
                oid_rfc4514_name(&oid_string(oid_c)),
                der_string_value(vtag, vcontent),
            ));
        }
        rdns.push(rdn);
    }
    let parts: Vec<String> = rdns
        .iter()
        .rev()
        .map(|rdn| {
            rdn.iter()
                .map(|(k, v)| format!("{}={}", k, rfc4514_escape(v)))
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    Ok(parts.join(","))
}

fn serial_hex(content: &[u8]) -> String {
    // INTEGER の中身を Python の format(serial, "X") と同じ表記にする
    let mut hex = String::new();
    for &b in content {
        hex.push_str(&format!("{:02X}", b));
    }
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

struct CertData {
    ders: Vec<Vec<u8>>,
    serial: String,
    issuer: String,
    subject: String,
    fingerprint: String,
    signing_key: SigningKey,
}

/// SEC1 (EC PRIVATE KEY) の DER から P-256 のスカラを取り出す。
fn sec1_scalar(der: &[u8]) -> Res<Vec<u8>> {
    let mut top = Der::new(der).seq()?;
    let _version = top.expect(0x02)?;
    let key = top.expect(0x04)?;
    Ok(key.to_vec())
}

fn load_signing_key(pem: &[u8], path: &str) -> Res<SigningKey> {
    for (typ, der) in pem_blocks(pem) {
        let scalar = match typ.as_str() {
            "EC PRIVATE KEY" => sec1_scalar(&der)?,
            "PRIVATE KEY" => {
                // PKCS#8: SEQ { version, algId, OCTET STRING(SEC1) }
                let mut top = Der::new(&der).seq()?;
                let _v = top.expect(0x02)?;
                let _alg = top.expect(0x30)?;
                let inner = top.expect(0x04)?;
                sec1_scalar(inner)?
            }
            _ => continue,
        };
        if scalar.len() != 32 {
            return err(&format!("{}: v1 は ECDSA P-256 の鍵のみ対応です", path));
        }
        let fb = p256::FieldBytes::from_slice(&scalar);
        return SigningKey::from_bytes(fb).map_err(|e| e.to_string().into());
    }
    err(&format!("{}: 秘密鍵が読めません", path))
}

fn load_cert_data(cert_path: &Path, key_path: &Path) -> Res<CertData> {
    let key_pem = std::fs::read(key_path)?;
    let signing_key = load_signing_key(&key_pem, &key_path.display().to_string())?;
    let cert_pem = std::fs::read(cert_path)?;
    let ders: Vec<Vec<u8>> = pem_blocks(&cert_pem)
        .into_iter()
        .filter(|(t, _)| t == "CERTIFICATE")
        .map(|(_, d)| d)
        .collect();
    if ders.is_empty() {
        return err(&format!("{}: 証明書が読めません", cert_path.display()));
    }
    // 先頭証明書から serial / issuer / subject を取り出す
    let leaf = &ders[0];
    let mut cert = Der::new(leaf).seq()?;
    let mut tbs = cert.seq()?;
    let (tag, first) = tbs.read_tlv()?;
    let serial_content: &[u8];
    let mut rest;
    if tag == 0xa0 {
        // [0] version の次が serial
        serial_content = tbs.expect(0x02)?;
    } else if tag == 0x02 {
        serial_content = first;
    } else {
        return err("cert: unexpected first field");
    }
    let _sig_alg = tbs.expect(0x30)?;
    let issuer_content = tbs.expect(0x30)?;
    let _validity = tbs.expect(0x30)?;
    let subject_content = tbs.expect(0x30)?;
    rest = ();
    let _ = &mut rest;
    Ok(CertData {
        serial: serial_hex(serial_content),
        issuer: name_rfc4514(issuer_content)?,
        subject: name_rfc4514(subject_content)?,
        fingerprint: sha256(leaf)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
        ders,
        signing_key,
    })
}

// ============================================================
//  設定 (config.hcrt)
// ============================================================
pub struct CertBundle {
    cert_path: PathBuf,
    key_path: PathBuf,
    data: RwLock<Arc<CertData>>,
    mtimes: Mutex<(SystemTime, SystemTime)>,
}

impl CertBundle {
    fn new(cert_path: PathBuf, key_path: PathBuf) -> Res<Arc<CertBundle>> {
        let data = load_cert_data(&cert_path, &key_path)?;
        let mt = Self::mtimes_of(&cert_path, &key_path)?;
        Ok(Arc::new(CertBundle {
            cert_path,
            key_path,
            data: RwLock::new(Arc::new(data)),
            mtimes: Mutex::new(mt),
        }))
    }
    fn mtimes_of(cert_path: &Path, key_path: &Path) -> Res<(SystemTime, SystemTime)> {
        Ok((
            std::fs::metadata(cert_path)?.modified()?,
            std::fs::metadata(key_path)?.modified()?,
        ))
    }
    fn snapshot(&self) -> Arc<CertData> {
        self.data.read().unwrap().clone()
    }
    fn reload_if_changed(&self) {
        let mt = match Self::mtimes_of(&self.cert_path, &self.key_path) {
            Ok(m) => m,
            Err(e) => {
                println!(
                    "[hcrt] cert reload failed ({}): {}",
                    self.cert_path.display(),
                    e
                );
                return;
            }
        };
        if mt == *self.mtimes.lock().unwrap() {
            return;
        }
        match load_cert_data(&self.cert_path, &self.key_path) {
            Ok(data) => {
                let serial = data.serial.clone();
                *self.data.write().unwrap() = Arc::new(data);
                *self.mtimes.lock().unwrap() = mt;
                println!(
                    "[hcrt] cert reloaded: {} (serial {}…)",
                    self.cert_path.display(),
                    &serial[..serial.len().min(16)]
                );
            }
            Err(e) => {
                println!(
                    "[hcrt] cert reload failed ({}): {}",
                    self.cert_path.display(),
                    e
                );
            }
        }
    }
}

struct Route {
    prefix: String,      // 例: "/a/*"
    static_part: String, // prefix から末尾 "/*" を除いたもの
    bundle: Arc<CertBundle>,
    root: PathBuf,
}

impl Route {
    fn new(prefix: &str, bundle: Arc<CertBundle>, root: PathBuf) -> Route {
        let static_part = if let Some(s) = prefix.strip_suffix("/*") {
            s.to_string()
        } else {
            prefix.to_string()
        };
        Route {
            prefix: prefix.to_string(),
            static_part,
            bundle,
            root,
        }
    }
    fn matches(&self, path: &str) -> bool {
        let sp = &self.static_part;
        if sp.is_empty() {
            return true; // "/*" は全マッチ
        }
        path == sp || path.starts_with(&format!("{}/", sp))
    }
    fn inner_path(&self, path: &str) -> String {
        let rest = &path[self.static_part.len()..];
        if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        }
    }
}

struct HostConfig {
    name: String,
    default_bundle: Option<Arc<CertBundle>>,
    routes: Vec<Route>,
}

impl HostConfig {
    fn match_route(&self, path: &str) -> Option<&Route> {
        let mut best: Option<&Route> = None;
        for r in &self.routes {
            if r.matches(path)
                && (best.is_none() || r.static_part.len() > best.unwrap().static_part.len())
            {
                best = Some(r);
            }
        }
        best
    }
}

struct Config {
    listen_addr: String,
    listen_port: u16,
    hosts: Vec<HostConfig>, // 定義順保持
    bundles: Vec<Arc<CertBundle>>,
}

impl Config {
    fn host_for_sni(&self, sni: Option<&str>) -> &HostConfig {
        if let Some(name) = sni {
            if let Some(h) = self.hosts.iter().find(|h| h.name == name) {
                return h;
            }
        }
        &self.hosts[0] // 既定は先頭の host
    }
}

fn load_config(path: &Path) -> Res<Config> {
    let base = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let text = std::fs::read_to_string(path)?;
    let mut lines: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim().to_string();
        if !line.is_empty() {
            lines.push(line);
        }
    }
    let absp = |p: &str| -> PathBuf {
        let pb = PathBuf::from(p);
        if pb.is_absolute() {
            pb
        } else {
            base.join(pb)
        }
    };
    let mut cfg = Config {
        listen_addr: "::".to_string(),
        listen_port: 443,
        hosts: Vec::new(),
        bundles: Vec::new(),
    };
    let mut bundle_map: HashMap<(String, String), Arc<CertBundle>> = HashMap::new();
    let mut get_bundle = |cfg_bundles: &mut Vec<Arc<CertBundle>>,
                          cert: PathBuf,
                          key: PathBuf|
     -> Res<Arc<CertBundle>> {
        let k = (
            cert.display().to_string(),
            key.display().to_string(),
        );
        if let Some(b) = bundle_map.get(&k) {
            return Ok(b.clone());
        }
        let b = CertBundle::new(cert, key)?;
        bundle_map.insert(k, b.clone());
        cfg_bundles.push(b.clone());
        Ok(b)
    };
    let mut cur: Option<usize> = None;
    for line in &lines {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks[0] == "listen" && toks.len() == 2 {
            let v = toks[1];
            if v.starts_with('[') && v.contains("]:") {
                let idx = v.find("]:").unwrap();
                cfg.listen_addr = v[1..idx].to_string();
                cfg.listen_port = v[idx + 2..].parse()?;
            } else if v.contains(':') {
                let idx = v.rfind(':').unwrap();
                cfg.listen_addr = v[..idx].to_string();
                cfg.listen_port = v[idx + 1..].parse()?;
            } else {
                cfg.listen_port = v.parse()?;
            }
        } else if toks[0] == "host" && toks.len() >= 2 {
            cfg.hosts.push(HostConfig {
                name: toks[1].to_string(),
                default_bundle: None,
                routes: Vec::new(),
            });
            cur = Some(cfg.hosts.len() - 1);
        } else if toks[0] == "}" {
            cur = None;
        } else if cur.is_some() && toks[0] == "default" && toks.len() == 3 {
            let b = get_bundle(&mut cfg.bundles, absp(toks[1]), absp(toks[2]))?;
            cfg.hosts[cur.unwrap()].default_bundle = Some(b);
        } else if cur.is_some() && toks[0] == "route" {
            // route <prefix> <cert> <key> root <dir>
            if toks.len() != 6 || toks[4] != "root" {
                return err(&format!("route 行の書式が違います: {}", line));
            }
            let b = get_bundle(&mut cfg.bundles, absp(toks[2]), absp(toks[3]))?;
            let root = absp(toks[5]);
            cfg.hosts[cur.unwrap()]
                .routes
                .push(Route::new(toks[1], b, root));
        } else if line == "{" {
            continue;
        } else {
            return err(&format!("解釈できない行: {}", line));
        }
    }
    if cfg.hosts.is_empty() {
        return err("host が1つも定義されていません");
    }
    for h in &cfg.hosts {
        if h.default_bundle.is_none() {
            return err(&format!("host {}: default 証明書がありません", h.name));
        }
        for r in &h.routes {
            if !r.root.is_dir() {
                return err(&format!(
                    "host {} route {}: root {} がありません",
                    h.name,
                    r.prefix,
                    r.root.display()
                ));
            }
        }
    }
    Ok(cfg)
}

// ============================================================
//  チケット / 巻き戻し記録
// ============================================================
static PENDING: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PENDING_IP: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const PENDING_TTL: f64 = 30.0;
const PENDING_IP_TTL: f64 = 10.0;

fn pending_set(lineage_hex: &str, fingerprint: &str, ip: Option<&str>) {
    PENDING
        .lock()
        .unwrap()
        .insert(lineage_hex.to_string(), (fingerprint.to_string(), Instant::now()));
    if let Some(ip) = ip {
        PENDING_IP
            .lock()
            .unwrap()
            .insert(ip.to_string(), (fingerprint.to_string(), Instant::now()));
    }
}

fn pending_pop_lineage(lineage_hex: &str) -> Option<String> {
    let ent = PENDING.lock().unwrap().remove(lineage_hex);
    match ent {
        Some((fp, t)) if t.elapsed().as_secs_f64() <= PENDING_TTL => Some(fp),
        _ => None,
    }
}

fn pending_pop_ip(ip: &str) -> Option<String> {
    let ent = PENDING_IP.lock().unwrap().remove(ip);
    match ent {
        Some((fp, t)) if t.elapsed().as_secs_f64() <= PENDING_IP_TTL => Some(fp),
        _ => None,
    }
}

static TICKET_KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn load_ticket_key(cfg_dir: &Path) -> PathBuf {
    let env_path = std::env::var("HCRT_TICKET_KEY").unwrap_or_default();
    let p = if env_path.is_empty() {
        cfg_dir.join(".hcrt-ticket-key.bin")
    } else {
        PathBuf::from(env_path)
    };
    if p.exists() {
        let _ = TICKET_KEY.set(std::fs::read(&p).unwrap_or_else(|_| rand_bytes(32)));
    } else {
        let key = rand_bytes(32);
        let _ = std::fs::write(&p, &key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
        let _ = TICKET_KEY.set(key);
    }
    p
}

fn ticket_key() -> &'static [u8] {
    TICKET_KEY.get().expect("ticket key loaded")
}

fn make_ticket(res_master: &[u8], ticket_nonce: &[u8], lineage: &[u8]) -> Vec<u8> {
    // 中身: lineage(8) || resumption_master_secret(32) || nonce長(1) || ticket_nonce || 有効期限(8)
    let nonce = rand_bytes(12);
    let expiry = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400;
    let mut pt = Vec::new();
    pt.extend_from_slice(lineage);
    pt.extend_from_slice(res_master);
    pt.push(ticket_nonce.len() as u8);
    pt.extend_from_slice(ticket_nonce);
    pt.extend_from_slice(&expiry.to_be_bytes());
    let cipher = Aes256Gcm::new_from_slice(ticket_key()).expect("ticket key len");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &[],
            },
        )
        .expect("ticket encrypt");
    let mut out = nonce;
    out.extend_from_slice(&ct);
    out
}

fn open_ticket(blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // (psk, lineage) を返す。期限切れ・改竄は None。
    if blob.len() < 13 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(ticket_key()).ok()?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&blob[..12]),
            Payload {
                msg: &blob[12..],
                aad: &[],
            },
        )
        .ok()?;
    if pt.len() < 41 {
        return None;
    }
    let lineage = pt[..8].to_vec();
    let res_master = &pt[8..40];
    let nl = pt[40] as usize;
    if pt.len() < 49 + nl {
        return None;
    }
    let ticket_nonce = &pt[41..41 + nl];
    let expiry = u64::from_be_bytes(pt[41 + nl..49 + nl].try_into().ok()?);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if expiry < now {
        return None;
    }
    Some((expand_label(res_master, b"resumption", ticket_nonce, 32), lineage))
}

// ============================================================
//  HKDF (RFC 8446)
// ============================================================
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut i: u8 = 1;
    while out.len() < length {
        let mut data = t.clone();
        data.extend_from_slice(info);
        data.push(i);
        t = hmac_sha256(prk, &data).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(length);
    out
}

fn expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut full = b"tls13 ".to_vec();
    full.extend_from_slice(label);
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, length)
}

fn derive_secret(secret: &[u8], label: &[u8], msg_hash: &[u8]) -> Vec<u8> {
    expand_label(secret, label, msg_hash, 32)
}

fn traffic_keys(secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        expand_label(secret, b"key", b"", 16),
        expand_label(secret, b"iv", b"", 12),
    )
}

fn aead_encrypt(key: &[u8], iv: &[u8], seq: u64, header: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    let cipher = Aes128Gcm::new_from_slice(key).expect("aead key len");
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .expect("aead encrypt")
}

fn aead_decrypt(
    key: &[u8],
    iv: &[u8],
    seq: u64,
    header: &[u8],
    ciphertext: &[u8],
) -> Res<Vec<u8>> {
    let mut nonce = iv.to_vec();
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|e| e.to_string().into())
}

// ============================================================
//  レコード層 / ClientHello 解析
// ============================================================
struct Conn {
    s: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    fn new(s: TcpStream) -> Conn {
        Conn { s, buf: Vec::new() }
    }
    fn read_exact(&mut self, n: usize) -> Res<Vec<u8>> {
        while self.buf.len() < n {
            let mut chunk = [0u8; 65536];
            let got = self.s.read(&mut chunk)?;
            if got == 0 {
                return err("eof");
            }
            self.buf.extend_from_slice(&chunk[..got]);
        }
        let out = self.buf[..n].to_vec();
        self.buf.drain(..n);
        Ok(out)
    }
    /// (5バイトヘッダ, ペイロード)
    fn read_record(&mut self) -> Res<(Vec<u8>, Vec<u8>)> {
        let hdr = self.read_exact(5)?;
        let ln = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let payload = self.read_exact(ln)?;
        Ok((hdr, payload))
    }
    fn send_record(&mut self, ctype: u8, payload: &[u8]) -> Res<()> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(ctype);
        out.extend_from_slice(b"\x03\x03");
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        self.s.write_all(&out)?;
        Ok(())
    }
    fn send_encrypted(
        &mut self,
        key: &[u8],
        iv: &[u8],
        seq: u64,
        inner_type: u8,
        payload: &[u8],
    ) -> Res<()> {
        let mut inner = payload.to_vec();
        inner.push(inner_type);
        let mut header = b"\x17\x03\x03".to_vec();
        header.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
        let ct = aead_encrypt(key, iv, seq, &header, &inner);
        self.send_record(23, &ct)
    }
}

struct ClientHello {
    suites: Vec<u16>,
    session_id: Vec<u8>,
    sni: Option<String>,
    x25519_pub: Option<Vec<u8>>,
    versions: Vec<u16>,
    alpn_list: Vec<Vec<u8>>,
    psk_identity: Option<Vec<u8>>,
    early_data_offered: bool,
}

fn parse_client_hello(msg: &[u8]) -> Res<ClientHello> {
    let body = &msg[4..];
    let mut p = 0usize;
    p += 2 + 32; // legacy_version + random
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let mut suites = Vec::new();
    let mut i = p;
    while i < p + cs_len {
        suites.push(u16::from_be_bytes([body[i], body[i + 1]]));
        i += 2;
    }
    p += cs_len;
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let mut exts: HashMap<u16, &[u8]> = HashMap::new();
    let end = p + ext_len;
    while p < end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        exts.insert(etype, &body[p..p + elen]);
        p += elen;
    }
    let session_id = {
        let sl = body[34] as usize;
        body[35..35 + sl].to_vec()
    };
    let mut out = ClientHello {
        suites,
        session_id,
        sni: None,
        x25519_pub: None,
        versions: Vec::new(),
        alpn_list: Vec::new(),
        psk_identity: None,
        early_data_offered: exts.contains_key(&42),
    };
    if let Some(d) = exts.get(&0) {
        // server_name (SNI)
        if d.len() >= 5 {
            let nl = u16::from_be_bytes([d[3], d[4]]) as usize;
            if d.len() >= 5 + nl {
                out.sni = Some(
                    String::from_utf8_lossy(&d[5..5 + nl])
                        .to_lowercase(),
                );
            }
        }
    }
    if let Some(d) = exts.get(&51) {
        // key_share
        let mut q = 2usize;
        while q + 4 <= d.len() {
            let g = u16::from_be_bytes([d[q], d[q + 1]]);
            let kl = u16::from_be_bytes([d[q + 2], d[q + 3]]) as usize;
            q += 4;
            if q + kl > d.len() {
                break;
            }
            if g == GROUP_X25519 {
                out.x25519_pub = Some(d[q..q + kl].to_vec());
            }
            q += kl;
        }
    }
    if let Some(d) = exts.get(&43) {
        // supported_versions
        let mut i = 1usize;
        while i + 2 <= d.len() {
            out.versions
                .push(u16::from_be_bytes([d[i], d[i + 1]]));
            i += 2;
        }
    }
    if let Some(d) = exts.get(&16) {
        // ALPN
        if d.len() >= 2 {
            let ln = u16::from_be_bytes([d[0], d[1]]) as usize;
            let mut q = 2usize;
            while q < 2 + ln && q < d.len() {
                let nl = d[q] as usize;
                if q + 1 + nl > d.len() {
                    break;
                }
                out.alpn_list.push(d[q + 1..q + 1 + nl].to_vec());
                q += 1 + nl;
            }
        }
    }
    if let Some(d) = exts.get(&41) {
        // pre_shared_key
        if d.len() >= 2 {
            let id_len = u16::from_be_bytes([d[0], d[1]]) as usize;
            let mut q = 2usize;
            let mut identities = Vec::new();
            while q + 2 <= 2 + id_len && q + 2 <= d.len() {
                let il = u16::from_be_bytes([d[q], d[q + 1]]) as usize;
                q += 2;
                if q + il + 4 > d.len() {
                    break;
                }
                identities.push(d[q..q + il].to_vec());
                q += il + 4;
            }
            out.psk_identity = identities.into_iter().next();
        }
    }
    Ok(out)
}

fn ext(etype: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&etype.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn hs_msg(mtype: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(mtype);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// 暗号化ペイロードの末尾ゼロを取り、(内部タイプ, 内容) に分ける。
fn split_inner(pt: &[u8]) -> Res<(u8, Vec<u8>)> {
    let mut end = pt.len();
    while end > 0 && pt[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return err("empty inner plaintext");
    }
    Ok((pt[end - 1], pt[..end - 1].to_vec()))
}

// ============================================================
//  アプリケーション層 IO
// ============================================================
/// クライアント app 鍵での復号読み取りと、サーバ app 鍵での暗号化送信。
/// KeyUpdate は透過的に処理する。
struct AppIO {
    c: Conn,
    c_secret: Vec<u8>,
    ck: Vec<u8>,
    civ: Vec<u8>,
    cseq: u64,
    sk: Vec<u8>,
    siv: Vec<u8>,
    sseq: u64,
}

impl AppIO {
    fn new(c: Conn, c_secret: Vec<u8>, s_key: Vec<u8>, s_iv: Vec<u8>, s_seq: u64) -> AppIO {
        let (ck, civ) = traffic_keys(&c_secret);
        AppIO {
            c,
            c_secret,
            ck,
            civ,
            cseq: 0,
            sk: s_key,
            siv: s_iv,
            sseq: s_seq,
        }
    }
    fn read_msg(&mut self) -> Res<(u8, Vec<u8>)> {
        loop {
            let (hdr, payload) = self.c.read_record()?;
            if hdr[0] == 20 {
                continue; // dummy CCS
            }
            let pt = aead_decrypt(&self.ck, &self.civ, self.cseq, &hdr, &payload)?;
            self.cseq += 1;
            let (itype, content) = split_inner(&pt)?;
            if itype == 21 {
                return err("alert");
            }
            if itype == 22 && !content.is_empty() && content[0] == 24 {
                // KeyUpdate
                self.c_secret = expand_label(&self.c_secret, b"ku", b"", 32);
                let (ck, civ) = traffic_keys(&self.c_secret);
                self.ck = ck;
                self.civ = civ;
                continue;
            }
            return Ok((itype, content));
        }
    }
    fn send_app(&mut self, data: &[u8]) -> Res<()> {
        for chunk in data.chunks(16000) {
            self.c.send_encrypted(&self.sk, &self.siv, self.sseq, 23, chunk)?;
            self.sseq += 1;
        }
        Ok(())
    }
}

// ============================================================
//  静的ファイル配信
// ============================================================
fn content_type_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn substitute_placeholders(
    data: &[u8],
    bundle: &CertData,
    how: &str,
    route_prefix: Option<&str>,
    host_name: &str,
) -> Res<Vec<u8>> {
    // HTML 内の %%HCRT_*%% を、この接続で実際に提示した証明書の情報で置換する
    if !data.windows(7).any(|w| w == b"%%HCRT_") {
        return Ok(data.to_vec());
    }
    let text = String::from_utf8(data.to_vec())?;
    let text = text
        .replace("%%HCRT_CERT_SERIAL%%", &bundle.serial)
        .replace("%%HCRT_CERT_ISSUER%%", &bundle.issuer)
        .replace("%%HCRT_CERT_SUBJECT%%", &bundle.subject)
        .replace("%%HCRT_CERT_FINGERPRINT%%", &bundle.fingerprint)
        .replace("%%HCRT_HOW%%", how)
        .replace("%%HCRT_ROUTE%%", route_prefix.unwrap_or("-"))
        .replace("%%HCRT_HOST%%", host_name);
    Ok(text.into_bytes())
}

fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}

/// (status, content_type, body) を返す。
fn serve_static(
    route: &Route,
    path: &str,
    bundle: &CertData,
    how: &str,
    host_name: &str,
) -> Res<(u16, &'static str, Vec<u8>)> {
    let inner = route.inner_path(path);
    let root = std::fs::canonicalize(&route.root)?;
    let rel = inner.trim_start_matches('/');
    let joined = normalize_path(&root.join(rel));
    let mut target = if joined.exists() {
        std::fs::canonicalize(&joined).unwrap_or(joined)
    } else {
        joined
    };
    if target != root && !target.starts_with(&root) {
        return Ok((403, "text/plain; charset=utf-8", b"403 Forbidden".to_vec()));
    }
    if target.is_dir() {
        target = target.join("index.html");
    } else if !target.exists() {
        let mut with_html = target.clone().into_os_string();
        with_html.push(".html");
        if Path::new(&with_html).exists() {
            target = PathBuf::from(with_html);
        }
    }
    if !target.is_file() {
        return Ok((
            404,
            "text/html; charset=utf-8",
            not_found_page(path, bundle, how, Some(route), host_name),
        ));
    }
    let ctype = content_type_for(&target);
    let data = std::fs::read(&target)?;
    let data = if ctype.starts_with("text/html") {
        substitute_placeholders(&data, bundle, how, Some(&route.prefix), host_name)?
    } else {
        data
    };
    Ok((200, ctype, data))
}

fn not_found_page(
    path: &str,
    bundle: &CertData,
    _how: &str,
    _route: Option<&Route>,
    _host_name: &str,
) -> Vec<u8> {
    let html = format!(
        "<!DOCTYPE html><html lang=\"ja\"><head><meta charset=\"utf-8\">\n\
         <title>404 Not Found</title></head><body>\n\
         <h1>404 Not Found</h1><p>{}</p>\n\
         <p>配信証明書シリアル: {} / 発行者: {}</p>\n\
         </body></html>",
        path, bundle.serial, bundle.issuer
    );
    html.into_bytes()
}

// ============================================================
//  HPACK (RFC 7541)
//  デコード: 静的/動的テーブル + Huffman 対応。
//  エンコード: リテラル (インデックスなし・Huffman なし) のみの最小実装。
// ============================================================
static HPACK_STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

static HUFFMAN_DECODE: LazyLock<HashMap<(u8, u32), u16>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for sym in 0..257usize {
        m.insert(
            (huffman_table::HUFFMAN_LEN[sym], huffman_table::HUFFMAN_CODE[sym]),
            sym as u16,
        );
    }
    m
});

fn huffman_decode(data: &[u8]) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    let mut code: u32 = 0;
    let mut len: u8 = 0;
    for &byte in data {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as u32;
            code = (code << 1) | bit;
            len += 1;
            if let Some(&sym) = HUFFMAN_DECODE.get(&(len, code)) {
                if sym == 256 {
                    return err("HPACK: EOS in huffman data");
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            } else if len >= 30 {
                return err("HPACK: invalid huffman code");
            }
        }
    }
    // 残りは EOS の prefix であるパディング (すべて 1) でなければならない
    if len > 0 && code != (1u32 << len) - 1 {
        return err("HPACK: bad huffman padding");
    }
    Ok(out)
}

struct HpackReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> HpackReader<'a> {
    fn read_int(&mut self, prefix_bits: u8) -> Res<u64> {
        if self.pos >= self.data.len() {
            return err("HPACK: truncated int");
        }
        let mask = (1u64 << prefix_bits) - 1;
        let mut value = (self.data[self.pos] as u64) & mask;
        self.pos += 1;
        if value < mask {
            return Ok(value);
        }
        let mut shift = 0u32;
        loop {
            if self.pos >= self.data.len() {
                return err("HPACK: truncated int cont");
            }
            let b = self.data[self.pos];
            self.pos += 1;
            value += ((b & 0x7f) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 56 {
                return err("HPACK: int too large");
            }
        }
        Ok(value)
    }
    fn read_string(&mut self) -> Res<Vec<u8>> {
        if self.pos >= self.data.len() {
            return err("HPACK: truncated string");
        }
        let huffman = self.data[self.pos] & 0x80 != 0;
        let len = self.read_int(7)? as usize;
        if self.pos + len > self.data.len() {
            return err("HPACK: string overlong");
        }
        let raw = &self.data[self.pos..self.pos + len];
        self.pos += len;
        if huffman {
            huffman_decode(raw)
        } else {
            Ok(raw.to_vec())
        }
    }
}

struct HpackDecoder {
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    dynamic_size: usize,
    max_dynamic: usize,
}

impl HpackDecoder {
    fn new() -> HpackDecoder {
        HpackDecoder {
            dynamic: VecDeque::new(),
            dynamic_size: 0,
            max_dynamic: 4096,
        }
    }
    fn entry(&self, index: u64) -> Res<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return err("HPACK: index 0");
        }
        if (index as usize) <= HPACK_STATIC.len() {
            let (n, v) = HPACK_STATIC[(index - 1) as usize];
            return Ok((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        let di = (index as usize) - HPACK_STATIC.len() - 1;
        match self.dynamic.get(di) {
            Some((n, v)) => Ok((n.clone(), v.clone())),
            None => err("HPACK: index out of range"),
        }
    }
    fn evict(&mut self) {
        while self.dynamic_size > self.max_dynamic {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.dynamic_size -= n.len() + v.len() + 32,
                None => break,
            }
        }
    }
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = name.len() + value.len() + 32;
        if size > self.max_dynamic {
            self.dynamic.clear();
            self.dynamic_size = 0;
            return;
        }
        self.dynamic_size += size;
        self.dynamic.push_front((name, value));
        self.evict();
    }
    fn read_name(&self, r: &mut HpackReader, prefix_bits: u8) -> Res<Vec<u8>> {
        // 呼び出し側で先頭バイトのインデックス部を読む
        let idx = r.read_int(prefix_bits)?;
        if idx == 0 {
            r.read_string()
        } else {
            Ok(self.entry(idx)?.0)
        }
    }
    fn decode(&mut self, block: &[u8]) -> Res<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut r = HpackReader { data: block, pos: 0 };
        let mut out = Vec::new();
        while r.pos < block.len() {
            let b = block[r.pos];
            if b & 0x80 != 0 {
                // Indexed Header Field
                let idx = r.read_int(7)?;
                out.push(self.entry(idx)?);
            } else if b & 0xc0 == 0x40 {
                // Literal with Incremental Indexing
                let name = self.read_name(&mut r, 6)?;
                let value = r.read_string()?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
            } else if b & 0xe0 == 0x20 {
                // Dynamic Table Size Update
                let n = r.read_int(5)? as usize;
                self.max_dynamic = n;
                self.evict();
            } else {
                // Literal without Indexing (0000xxxx) / Never Indexed (0001xxxx)
                let name = self.read_name(&mut r, 4)?;
                let value = r.read_string()?;
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

fn hpack_write_int(out: &mut Vec<u8>, prefix_bits: u8, prefix_value: u8, mut value: u64) {
    let mask = (1u64 << prefix_bits) - 1;
    if value < mask {
        out.push(prefix_value | value as u8);
    } else {
        out.push(prefix_value | mask as u8);
        value -= mask;
        while value >= 128 {
            out.push(((value % 128) as u8) | 0x80);
            value /= 128;
        }
        out.push(value as u8);
    }
}

fn hpack_write_string(out: &mut Vec<u8>, data: &[u8]) {
    hpack_write_int(out, 7, 0, data.len() as u64);
    out.extend_from_slice(data);
}

/// リテラル (インデックスなし・新規名前) のみでエンコードする最小実装。
fn hpack_encode_literal(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        hpack_write_int(&mut out, 4, 0x00, 0); // without indexing, new name
        hpack_write_string(&mut out, name);
        hpack_write_string(&mut out, value);
    }
    out
}

// ============================================================
//  HTTP/2 (ChronoCert 巻き戻し + 静的配信)
// ============================================================
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PUSH_PROMISE: u8 = 0x5;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const H2_NO_ERROR: u32 = 0x0;
const H2_REFUSED_STREAM: u32 = 0x7;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct H2StreamState {
    headers: Vec<(String, String)>,
    ended: bool,
}

struct H2Conn<'a> {
    appio: &'a mut AppIO,
    inbuf: Vec<u8>,
    preface_done: bool,
    decoder: HpackDecoder,
    streams: HashMap<u32, H2StreamState>,
    done: HashMap<u32, ()>,
    last_processed: u32,
    frag_id: Option<u32>,
    frag_buf: Vec<u8>,
    frag_end_stream: bool,
    frag_is_headers: bool,
}

impl<'a> H2Conn<'a> {
    fn new(appio: &'a mut AppIO, prefix: Vec<u8>) -> H2Conn<'a> {
        H2Conn {
            appio,
            inbuf: prefix,
            preface_done: false,
            decoder: HpackDecoder::new(),
            streams: HashMap::new(),
            done: HashMap::new(),
            last_processed: 0,
            frag_id: None,
            frag_buf: Vec::new(),
            frag_end_stream: false,
            frag_is_headers: false,
        }
    }

    fn fill(&mut self) -> Res<()> {
        let (itype, content) = self.appio.read_msg()?;
        if itype == 23 {
            self.inbuf.extend_from_slice(&content);
        }
        Ok(())
    }

    fn read_exact(&mut self, n: usize) -> Res<Vec<u8>> {
        while self.inbuf.len() < n {
            self.fill()?;
        }
        let out = self.inbuf[..n].to_vec();
        self.inbuf.drain(..n);
        Ok(out)
    }

    /// (type, flags, stream_id, payload)
    fn read_frame(&mut self) -> Res<(u8, u8, u32, Vec<u8>)> {
        if !self.preface_done {
            let p = self.read_exact(24)?;
            if p != CLIENT_PREFACE {
                return err("h2: bad client preface");
            }
            self.preface_done = true;
        }
        let hdr = self.read_exact(9)?;
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
        let payload = self.read_exact(len)?;
        Ok((ftype, flags, sid, payload))
    }

    fn send_frame(&mut self, ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Res<()> {
        let mut out = Vec::with_capacity(9 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.push(ftype);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);
        self.appio.send_app(&out)
    }

    fn send_headers(&mut self, stream_id: u32, headers: Vec<(Vec<u8>, Vec<u8>)>, end_stream: bool) -> Res<()> {
        let block = hpack_encode_literal(&headers);
        let mut first = true;
        let mut offset = 0;
        loop {
            let chunk_len = std::cmp::min(16384, block.len() - offset);
            let is_last = offset + chunk_len >= block.len();
            let mut flags = 0u8;
            if is_last {
                flags |= 0x4; // END_HEADERS
            }
            if first && end_stream {
                flags |= 0x1; // END_STREAM
            }
            let ftype = if first { FRAME_HEADERS } else { FRAME_CONTINUATION };
            self.send_frame(ftype, flags, stream_id, &block[offset..offset + chunk_len])?;
            offset += chunk_len;
            first = false;
            if is_last {
                break;
            }
        }
        Ok(())
    }

    fn send_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> Res<()> {
        if data.is_empty() {
            if end_stream {
                self.send_frame(FRAME_DATA, 0x1, stream_id, &[])?;
            }
            return Ok(());
        }
        let mut offset = 0;
        while offset < data.len() {
            let chunk_len = std::cmp::min(16384, data.len() - offset);
            let is_last = offset + chunk_len >= data.len();
            let flags = if is_last && end_stream { 0x1 } else { 0x0 };
            self.send_frame(FRAME_DATA, flags, stream_id, &data[offset..offset + chunk_len])?;
            offset += chunk_len;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process(
        &mut self,
        stream_id: u32,
        headers: &HashMap<String, String>,
        peer: &str,
        host: &HostConfig,
        bound_bundle: &CertData,
        lineage_hex: &str,
        how: &str,
    ) -> Res<()> {
        if self.done.contains_key(&stream_id) {
            return Ok(());
        }
        self.done.insert(stream_id, ());
        self.streams.remove(&stream_id);
        let method = headers.get(":method").cloned().unwrap_or_else(|| "GET".to_string());
        let raw_path = headers.get(":path").cloned().unwrap_or_else(|| "/".to_string());
        let path = raw_path.split('?').next().unwrap_or("/").to_string();
        let route = host.match_route(&path);
        let sfm = headers.get("sec-fetch-mode");
        let sfd = headers.get("sec-fetch-dest");
        let is_nav = sfm.map(|v| v == "navigate").unwrap_or(false)
            || sfd.map(|v| v == "document").unwrap_or(false)
            || (sfm.is_none() && route.is_some());
        if is_nav {
            if let Some(r) = route {
                if r.bundle.snapshot().fingerprint != bound_bundle.fingerprint {
                    pending_set(lineage_hex, &r.bundle.snapshot().fingerprint, Some(peer));
                    println!(
                        "[{}] REWIND: bound_fp={}… requested route={} -> RST_STREAM(REFUSED) + GOAWAY",
                        peer,
                        &bound_bundle.fingerprint[..8],
                        r.prefix
                    );
                    let _ = self.send_frame(
                        FRAME_RST_STREAM,
                        0,
                        stream_id,
                        &H2_REFUSED_STREAM.to_be_bytes(),
                    );
                    let mut goaway = Vec::new();
                    goaway.extend_from_slice(&self.last_processed.to_be_bytes());
                    goaway.extend_from_slice(&H2_NO_ERROR.to_be_bytes());
                    let _ = self.send_frame(FRAME_GOAWAY, 0, 0, &goaway);
                    std::thread::sleep(Duration::from_millis(250));
                    return err("rewound");
                }
            }
        }
        let (status, ctype, body): (u16, &str, Vec<u8>) = if method != "GET" && method != "HEAD" {
            (405, "text/plain; charset=utf-8", b"405 Method Not Allowed".to_vec())
        } else if route.is_none() {
            (
                404,
                "text/html; charset=utf-8",
                not_found_page(&path, bound_bundle, how, None, &host.name),
            )
        } else {
            serve_static(route.unwrap(), &path, bound_bundle, how, &host.name)?
        };
        println!(
            "[{}] H2 {} {} -> {} (cert serial {}…)",
            peer,
            method,
            path,
            status,
            &bound_bundle.serial[..bound_bundle.serial.len().min(12)]
        );
        let resp_headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":status".to_vec(), status.to_string().into_bytes()),
            (b"content-type".to_vec(), ctype.as_bytes().to_vec()),
            (b"cache-control".to_vec(), b"no-store".to_vec()),
            (b"content-length".to_vec(), body.len().to_string().into_bytes()),
        ];
        if method != "HEAD" && !body.is_empty() {
            self.send_headers(stream_id, resp_headers, false)?;
            self.send_data(stream_id, &body, true)?;
        } else {
            self.send_headers(stream_id, resp_headers, true)?;
        }
        self.last_processed = std::cmp::max(self.last_processed, stream_id);
        Ok(())
    }

    fn run(
        &mut self,
        peer: &str,
        host: &HostConfig,
        bound_bundle: &CertData,
        lineage_hex: &str,
        how: &str,
    ) -> Res<()> {
        // サーバ SETTINGS を先に送る (h2 ライブラリの initiate_connection 相当)
        self.send_frame(FRAME_SETTINGS, 0, 0, &[])?;
        loop {
            let (ftype, flags, sid, payload) = self.read_frame()?;
            match ftype {
                FRAME_SETTINGS => {
                    if flags & 0x1 == 0 {
                        self.send_frame(FRAME_SETTINGS, 0x1, 0, &[])?;
                    }
                }
                FRAME_PING => {
                    if flags & 0x1 == 0 && payload.len() == 8 {
                        self.send_frame(FRAME_PING, 0x1, 0, &payload)?;
                    }
                }
                FRAME_GOAWAY => {
                    return err("goaway received");
                }
                FRAME_HEADERS | FRAME_CONTINUATION | FRAME_PUSH_PROMISE => {
                    if ftype == FRAME_HEADERS {
                        if self.frag_id.is_some() {
                            return err("h2: header block already in progress");
                        }
                        self.frag_id = Some(sid);
                        self.frag_buf = payload.clone();
                        self.frag_end_stream = flags & 0x1 != 0;
                        self.frag_is_headers = true;
                    } else if ftype == FRAME_PUSH_PROMISE {
                        if self.frag_id.is_some() {
                            return err("h2: header block already in progress");
                        }
                        self.frag_id = Some(sid);
                        // PUSH_PROMISE の先頭4バイトは promised stream id
                        self.frag_buf = if payload.len() >= 4 {
                            payload[4..].to_vec()
                        } else {
                            Vec::new()
                        };
                        self.frag_end_stream = false;
                        self.frag_is_headers = false;
                    } else {
                        if self.frag_id != Some(sid) {
                            return err("h2: unexpected CONTINUATION");
                        }
                        self.frag_buf.extend_from_slice(&payload);
                    }
                    if flags & 0x4 != 0 {
                        // END_HEADERS
                        let block = std::mem::take(&mut self.frag_buf);
                        let was_headers = self.frag_is_headers;
                        let end_stream = self.frag_end_stream;
                        self.frag_id = None;
                        if was_headers {
                            let decoded = self.decoder.decode(&block)?;
                            let mut map: HashMap<String, String> = HashMap::new();
                            for (n, v) in decoded {
                                map.insert(
                                    String::from_utf8_lossy(&n).into_owned(),
                                    String::from_utf8_lossy(&v).into_owned(),
                                );
                            }
                            let ended = end_stream;
                            self.streams.insert(
                                sid,
                                H2StreamState {
                                    headers: decoded_map_to_vec(&map),
                                    ended,
                                },
                            );
                            if ended {
                                self.process(sid, &map, peer, host, bound_bundle, lineage_hex, how)?;
                            }
                        }
                    }
                }
                FRAME_DATA => {
                    if !payload.is_empty() {
                        let _ = self.send_frame(
                            FRAME_WINDOW_UPDATE,
                            0,
                            sid,
                            &1073741823u32.to_be_bytes(),
                        );
                    }
                    if flags & 0x1 != 0 {
                        if let Some(st) = self.streams.get(&sid) {
                            let map = vec_to_map(&st.headers);
                            self.process(sid, &map, peer, host, bound_bundle, lineage_hex, how)?;
                        }
                    }
                }
                FRAME_RST_STREAM => {
                    self.streams.remove(&sid);
                }
                _ => {
                    // PRIORITY / WINDOW_UPDATE / 未知フレームは読み捨てる
                }
            }
        }
    }
}

fn decoded_map_to_vec(map: &HashMap<String, String>) -> Vec<(String, String)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn vec_to_map(v: &[(String, String)]) -> HashMap<String, String> {
    v.iter().cloned().collect()
}

fn run_h2(
    appio: &mut AppIO,
    prefix: Vec<u8>,
    peer: &str,
    host: &HostConfig,
    bound_bundle: &CertData,
    lineage_hex: &str,
    how: &str,
) -> Res<()> {
    let mut h2 = H2Conn::new(appio, prefix);
    h2.run(peer, host, bound_bundle, lineage_hex, how)
}

// ============================================================
//  接続処理
// ============================================================
impl Conn {
    fn set_read_timeout(&self, d: Option<Duration>) -> Res<()> {
        self.s.set_read_timeout(d)?;
        Ok(())
    }
}

fn hex_lower(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn latin1(data: &[u8]) -> String {
    data.iter().map(|&b| b as char).collect()
}

#[allow(clippy::too_many_arguments)]
fn send_hs(
    c: &mut Conn,
    transcript: &mut Sha256,
    key: &[u8],
    iv: &[u8],
    seq: &mut u64,
    mtype: u8,
    body: &[u8],
) -> Res<()> {
    let m = hs_msg(mtype, body);
    transcript.update(&m);
    c.send_encrypted(key, iv, *seq, 22, &m)?;
    *seq += 1;
    Ok(())
}

fn transcript_hash(t: &Sha256) -> [u8; 32] {
    t.clone().finalize().into()
}

fn handle(sock: TcpStream, cfg: Arc<Config>) {
    let peer_addr = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    let peer_ip = sock
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "?".to_string());
    if let Err(e) = handle_inner(sock, &peer_ip, &peer_addr, &cfg) {
        println!("[{}] error: {}", peer_addr, e);
    }
}

fn handle_inner(sock: TcpStream, peer_ip: &str, peer_log: &str, cfg: &Config) -> Res<()> {
    let mut c = Conn::new(sock);
    // --- ClientHello ---
    let mut hsbuf: Vec<u8> = Vec::new();
    loop {
        if hsbuf.len() >= 4 {
            let total = 4 + (((hsbuf[1] as usize) << 16) | ((hsbuf[2] as usize) << 8) | hsbuf[3] as usize);
            if hsbuf.len() >= total {
                break;
            }
        }
        let (hdr, payload) = c.read_record()?;
        if hdr[0] == 22 {
            hsbuf.extend_from_slice(&payload);
        }
    }
    let total = 4 + (((hsbuf[1] as usize) << 16) | ((hsbuf[2] as usize) << 8) | hsbuf[3] as usize);
    let ch_msg = hsbuf[..total].to_vec();
    let ch = parse_client_hello(&ch_msg)?;
    if !ch.versions.contains(&0x0304) || !ch.suites.contains(&SUITE) || ch.x25519_pub.is_none() {
        println!("[{}] unsupported ClientHello", peer_log);
        return Ok(());
    }
    let host = cfg.host_for_sni(ch.sni.as_deref());
    let default_data = host
        .default_bundle
        .as_ref()
        .expect("validated in load_config")
        .snapshot();
    let mut bundles_by_fp: HashMap<String, Arc<CertData>> = HashMap::new();
    bundles_by_fp.insert(default_data.fingerprint.clone(), default_data.clone());
    for r in &host.routes {
        let d = r.bundle.snapshot();
        bundles_by_fp.insert(d.fingerprint.clone(), d);
    }

    // --- チケット解決 (系列の引き継ぎ) ---
    let opened = ch.psk_identity.as_deref().and_then(open_ticket);
    let psk: Option<Vec<u8>> = opened.as_ref().map(|(p, _)| p.clone());
    let lineage: Vec<u8> = opened
        .as_ref()
        .map(|(_, l)| l.clone())
        .unwrap_or_else(|| rand_bytes(8));
    let lineage_hex = hex_lower(&lineage);

    // --- early data 覗き見 (0-RTT 方式) ---
    let mut peeked_path: Option<String> = None;
    if let Some(psk_bytes) = &psk {
        if ch.early_data_offered {
            let early_secret = hkdf_extract(&[0u8; 32], psk_bytes);
            let cet = derive_secret(&early_secret, b"c e traffic", &sha256(&ch_msg));
            let (ek, eiv) = traffic_keys(&cet);
            let mut seq: u64 = 0;
            let mut data: Vec<u8> = Vec::new();
            let _ = c.set_read_timeout(Some(Duration::from_millis(1200)));
            loop {
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                match c.read_record() {
                    Ok((hdr, payload)) => {
                        if hdr[0] == 20 {
                            continue;
                        }
                        if hdr[0] != 23 {
                            break;
                        }
                        match aead_decrypt(&ek, &eiv, seq, &hdr, &payload) {
                            Ok(pt) => {
                                seq += 1;
                                match split_inner(&pt) {
                                    Ok((itype, content)) => {
                                        if itype == 23 {
                                            data.extend_from_slice(&content);
                                        }
                                    }
                                    Err(e) => {
                                        println!("[{}] early data read note: {}", peer_log, e);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                println!("[{}] early data read note: {}", peer_log, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        println!("[{}] early data read note: {}", peer_log, e);
                        break;
                    }
                }
            }
            let _ = c.set_read_timeout(None);
            if !data.is_empty() {
                let first = match data.windows(2).position(|w| w == b"\r\n") {
                    Some(i) => &data[..i],
                    None => &data[..],
                };
                let parts: Vec<String> = latin1(first).split(' ').map(|s| s.to_string()).collect();
                if parts.len() >= 2 {
                    peeked_path = Some(parts[1].clone());
                }
            }
            println!(
                "[{}] PEEKED early data path: {}",
                peer_log,
                peeked_path.as_deref().unwrap_or("None")
            );
        }
    }

    // --- 証明書選択: early data > 巻き戻し予定 (系列→IP) > 既定 ---
    let mut how = "既定".to_string();
    let mut chosen: Arc<CertData> = default_data.clone();
    if let Some(pp) = &peeked_path {
        let pth = pp.split('?').next().unwrap_or("");
        if let Some(r) = host.match_route(pth) {
            chosen = r.bundle.snapshot();
            how = format!("0-RTT early data 覗き見（パス {}）", pp);
        }
    } else {
        let mut selected = false;
        if let Some(fp) = pending_pop_lineage(&lineage_hex) {
            if let Some(b) = bundles_by_fp.get(&fp) {
                chosen = b.clone();
                how = "ChronoCert 巻き戻し（系列ID）".to_string();
                selected = true;
            }
        }
        if !selected && opened.is_none() {
            if let Some(fp) = pending_pop_ip(peer_ip) {
                if let Some(b) = bundles_by_fp.get(&fp) {
                    chosen = b.clone();
                    how = "ChronoCert 巻き戻し（同一IPフォールバック）".to_string();
                }
            }
        }
    }
    let alpn_str = {
        let items: Vec<String> = ch
            .alpn_list
            .iter()
            .map(|p| format!("b'{}'", latin1(p)))
            .collect();
        format!("[{}]", items.join(", "))
    };
    println!(
        "[{}] host={} cert serial={}… how={} psk={} alpn={}",
        peer_log,
        host.name,
        &chosen.serial[..chosen.serial.len().min(16)],
        how,
        if psk.is_some() { "ok" } else { "no" },
        alpn_str
    );

    // --- ALPN: h2 優先 ---
    let proto: Option<Vec<u8>> = if ch.alpn_list.iter().any(|p| p == b"h2") {
        Some(b"h2".to_vec())
    } else if ch.alpn_list.iter().any(|p| p == b"http/1.1") {
        Some(b"http/1.1".to_vec())
    } else {
        None
    };

    // --- ServerHello (PSK は拒否してフルハンドシェイク) ---
    let ecdhe_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ecdhe_public = x25519_dalek::PublicKey::from(&ecdhe_secret);
    let client_pub_bytes: [u8; 32] = ch
        .x25519_pub
        .as_ref()
        .unwrap()
        .as_slice()
        .try_into()
        .map_err(|_| "bad x25519 key length")?;
    let client_pub = x25519_dalek::PublicKey::from(client_pub_bytes);
    let shared = ecdhe_secret.diffie_hellman(&client_pub);
    let server_random = rand_bytes(32);
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(b"\x03\x03");
    sh_body.extend_from_slice(&server_random);
    sh_body.push(ch.session_id.len() as u8);
    sh_body.extend_from_slice(&ch.session_id);
    sh_body.extend_from_slice(&SUITE.to_be_bytes());
    sh_body.push(0);
    let mut sh_exts = Vec::new();
    sh_exts.extend_from_slice(&ext(43, b"\x03\x04"));
    let mut ks = Vec::new();
    ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
    ks.extend_from_slice(&32u16.to_be_bytes());
    ks.extend_from_slice(ecdhe_public.as_bytes());
    sh_exts.extend_from_slice(&ext(51, &ks));
    sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&sh_exts);
    let sh_msg = hs_msg(2, &sh_body);
    let mut transcript = Sha256::new();
    transcript.update(&ch_msg);
    transcript.update(&sh_msg);
    c.send_record(22, &sh_msg)?;

    let early0 = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived = derive_secret(&early0, b"derived", &sha256(b""));
    let hs_secret = hkdf_extract(&derived, shared.as_bytes());
    let th = transcript_hash(&transcript);
    let s_hs = derive_secret(&hs_secret, b"s hs traffic", &th);
    let c_hs = derive_secret(&hs_secret, b"c hs traffic", &th);
    let (sk, siv) = traffic_keys(&s_hs);
    let (ck, civ) = traffic_keys(&c_hs);
    let mut sseq: u64 = 0;

    let mut ee_exts = Vec::new();
    if let Some(p) = &proto {
        let mut v = Vec::new();
        v.extend_from_slice(&(1 + p.len() as u16).to_be_bytes());
        v.push(p.len() as u8);
        v.extend_from_slice(p);
        ee_exts.extend_from_slice(&ext(16, &v));
    }
    let mut ee_body = Vec::new();
    ee_body.extend_from_slice(&(ee_exts.len() as u16).to_be_bytes());
    ee_body.extend_from_slice(&ee_exts);
    send_hs(&mut c, &mut transcript, &sk, &siv, &mut sseq, 8, &ee_body)?;

    let mut entries = Vec::new();
    for der in &chosen.ders {
        entries.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        entries.extend_from_slice(der);
        entries.extend_from_slice(&0u16.to_be_bytes());
    }
    let mut cert_body = Vec::new();
    cert_body.push(0);
    cert_body.extend_from_slice(&(entries.len() as u32).to_be_bytes()[1..]);
    cert_body.extend_from_slice(&entries);
    send_hs(&mut c, &mut transcript, &sk, &siv, &mut sseq, 11, &cert_body)?;

    let mut sig_input = vec![0x20u8; 64];
    sig_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    sig_input.push(0);
    sig_input.extend_from_slice(&transcript_hash(&transcript));
    let signature: Signature = chosen.signing_key.sign(&sig_input);
    let sig_bytes: Vec<u8> = signature.to_der().as_bytes().to_vec();
    let mut cv_body = Vec::new();
    cv_body.extend_from_slice(&SIG_ECDSA256.to_be_bytes());
    cv_body.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    cv_body.extend_from_slice(&sig_bytes);
    send_hs(&mut c, &mut transcript, &sk, &siv, &mut sseq, 15, &cv_body)?;

    let fin_key_s = expand_label(&s_hs, b"finished", b"", 32);
    let verify_s = hmac_sha256(&fin_key_s, &transcript_hash(&transcript));
    send_hs(&mut c, &mut transcript, &sk, &siv, &mut sseq, 20, &verify_s)?;
    let hash_after_sfin = transcript_hash(&transcript);

    // --- クライアント Finished (検証あり) ---
    let fin_key_c = expand_label(&c_hs, b"finished", b"", 32);
    let mut cseq: u64 = 0;
    let mut got_finished = false;
    let mut app_buf: Vec<u8> = Vec::new();
    while !got_finished {
        let (hdr, payload) = c.read_record()?;
        if hdr[0] == 20 {
            continue;
        }
        let pt = match aead_decrypt(&ck, &civ, cseq, &hdr, &payload) {
            Ok(p) => p,
            Err(_) => continue, // 証明書を拒否して切断するクライアント等のレコードは読み飛ばす
        };
        cseq += 1;
        let (itype, content) = split_inner(&pt)?;
        if itype == 22 {
            if !content.is_empty() && content[0] == 20 {
                // Finished
                let expected = hmac_sha256(&fin_key_c, &transcript_hash(&transcript));
                if content.len() < 4 || expected[..] != content[4..] {
                    return err("client Finished verify failed");
                }
                got_finished = true;
            }
            transcript.update(&content);
        } else if itype == 23 {
            app_buf.extend_from_slice(&content);
        }
    }

    // --- アプリケーション鍵 ---
    let derived2 = derive_secret(&hs_secret, b"derived", &sha256(b""));
    let master = hkdf_extract(&derived2, &[0u8; 32]);
    let c_ap = derive_secret(&master, b"c ap traffic", &hash_after_sfin);
    let s_ap = derive_secret(&master, b"s ap traffic", &hash_after_sfin);
    let (ak_s, aiv_s) = traffic_keys(&s_ap);

    // NewSessionTicket x2 (early_data 許可 + 系列ID 刻印)
    let res_master = derive_secret(&master, b"res master", &transcript_hash(&transcript));
    let mut aseq_s: u64 = 0;
    for _ in 0..2 {
        let age_add = u32::from_be_bytes(rand_bytes(4).try_into().unwrap());
        let ticket_nonce = rand_bytes(8);
        let ticket = make_ticket(&res_master, &ticket_nonce, &lineage);
        let nst_exts = ext(42, &16384u32.to_be_bytes());
        let mut nst_body = Vec::new();
        nst_body.extend_from_slice(&86400u32.to_be_bytes());
        nst_body.extend_from_slice(&age_add.to_be_bytes());
        nst_body.push(ticket_nonce.len() as u8);
        nst_body.extend_from_slice(&ticket_nonce);
        nst_body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        nst_body.extend_from_slice(&ticket);
        nst_body.extend_from_slice(&(nst_exts.len() as u16).to_be_bytes());
        nst_body.extend_from_slice(&nst_exts);
        let m = hs_msg(4, &nst_body);
        c.send_encrypted(&ak_s, &aiv_s, aseq_s, 22, &m)?;
        aseq_s += 1;
    }

    let mut appio = AppIO::new(c, c_ap, ak_s, aiv_s, aseq_s);

    if proto.as_deref() == Some(b"h2".as_slice()) {
        run_h2(&mut appio, app_buf, peer_ip, host, &chosen, &lineage_hex, &how)?;
    } else {
        // --- HTTP/1.1 (1リクエストで閉じる) ---
        let mut buf = app_buf;
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let (itype, content) = appio.read_msg()?;
            if itype == 23 {
                buf.extend_from_slice(&content);
            }
        }
        let first = match buf.windows(2).position(|w| w == b"\r\n") {
            Some(i) => &buf[..i],
            None => &buf[..],
        };
        let line = latin1(first);
        let parts: Vec<&str> = line.split(' ').collect();
        let method = if parts.is_empty() { "GET" } else { parts[0] };
        let raw_path = if parts.len() >= 2 { parts[1] } else { "/" };
        let path = raw_path.split('?').next().unwrap_or("/").to_string();
        let route = host.match_route(&path);
        let (status, ctype, body): (u16, &str, Vec<u8>) = if method != "GET" && method != "HEAD" {
            (405, "text/plain; charset=utf-8", b"405 Method Not Allowed".to_vec())
        } else if route.is_none() {
            (
                404,
                "text/html; charset=utf-8",
                not_found_page(&path, &chosen, &how, None, &host.name),
            )
        } else {
            serve_static(route.unwrap(), &path, &chosen, &how, &host.name)?
        };
        println!(
            "[{}] H1 {} {} -> {} (cert serial {}…)",
            peer_log,
            method,
            path,
            status,
            &chosen.serial[..chosen.serial.len().min(12)]
        );
        let mut resp = format!(
            "HTTP/1.1 {} {}\r\n",
            status,
            if status == 200 { "OK" } else { "Error" }
        )
        .into_bytes();
        resp.extend_from_slice(format!("Content-Type: {}\r\n", ctype).as_bytes());
        resp.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        resp.extend_from_slice(b"Connection: close\r\n\r\n");
        if method != "HEAD" {
            resp.extend_from_slice(&body);
        }
        appio.send_app(&resp)?;
    }
    Ok(())
}

// ============================================================
//  main
// ============================================================
fn watcher(cfg: Arc<Config>) {
    loop {
        std::thread::sleep(Duration::from_secs(20));
        for b in &cfg.bundles {
            b.reload_if_changed();
        }
    }
}

fn main() {
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.hcrt".to_string());
    let cfg = match load_config(Path::new(&cfg_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[hcrt] config error: {}", e);
            std::process::exit(1);
        }
    };
    let cfg = Arc::new(cfg);
    let cfg_abs = std::fs::canonicalize(&cfg_path).unwrap_or_else(|_| PathBuf::from(&cfg_path));
    let cfg_dir = cfg_abs
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let key_path = load_ticket_key(&cfg_dir);
    println!("[hcrt] config={} ticket_key={}", cfg_path, key_path.display());
    for h in &cfg.hosts {
        let def = h.default_bundle.as_ref().unwrap().snapshot();
        let routes: Vec<&str> = h.routes.iter().map(|r| r.prefix.as_str()).collect();
        println!(
            "[hcrt] host {}: default serial={}… routes={:?}",
            h.name,
            &def.serial[..def.serial.len().min(16)],
            routes
        );
    }
    {
        let cfg2 = cfg.clone();
        std::thread::spawn(move || watcher(cfg2));
    }
    let addr = cfg.listen_addr.clone();
    let port = cfg.listen_port;
    let bind = if addr.contains(':') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[hcrt] bind {} failed: {}", bind, e);
            std::process::exit(1);
        }
    };
    println!("[hcrt] Haruharu Cert Routing listening on [{}]:{}", addr, port);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let cfg2 = cfg.clone();
                std::thread::spawn(move || handle(s, cfg2));
            }
            Err(_) => continue,
        }
    }
}
