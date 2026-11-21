//! DNS lookups for the email pack, behind a trait so tests feed records and CI
//! never touches real DNS. [`UdpResolver`] is the live implementation: a small
//! stub resolver that asks recursive servers over UDP.
use crate::gateway::{BoxFut, NetworkGuard, OFFLINE_ENV};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The name does not exist (NXDOMAIN) or has no records of the type.
    NotFound,
    /// The lookup failed (timeout, server failure, network disabled).
    Failed(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such record"),
            Self::Failed(e) => write!(f, "lookup failed: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordType {
    Txt,
    Cname,
    Mx,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            Self::Txt => 16,
            Self::Cname => 5,
            Self::Mx => 15,
        }
    }
}

pub trait Resolver: Send + Sync {
    /// Record data as strings: TXT strings joined per record, CNAME targets,
    /// MX exchange host names.
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>>;
}

/// A resolver that refuses every lookup (no DNS configured).
pub struct NoDns;

impl Resolver for NoDns {
    fn lookup<'a>(
        &'a self,
        _name: &'a str,
        _kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async { Err(DnsError::Failed("DNS lookups are not configured".into())) })
    }
}

/// Fixed records for tests. Names are matched case-insensitively.
#[derive(Default, Clone)]
pub struct StaticDns {
    records: BTreeMap<(String, RecordType), Vec<String>>,
    failing: BTreeSet<(String, RecordType)>,
}

impl StaticDns {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, name: &str, kind: RecordType, values: &[&str]) -> Self {
        self.records.insert(
            (name.to_ascii_lowercase(), kind),
            values.iter().map(|v| (*v).to_owned()).collect(),
        );
        self
    }
    /// Make lookups of `name` and `kind` fail (timeout, SERVFAIL).
    pub fn failing(mut self, name: &str, kind: RecordType) -> Self {
        self.failing.insert((name.to_ascii_lowercase(), kind));
        self
    }
}

impl Resolver for StaticDns {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            let key = (name.to_ascii_lowercase(), kind);
            if self.failing.contains(&key) {
                return Err(DnsError::Failed("timed out (fixture)".into()));
            }
            match self.records.get(&key) {
                Some(v) if !v.is_empty() => Ok(v.clone()),
                _ => Err(DnsError::NotFound),
            }
        })
    }
}

/// Well-known public resolvers (Cloudflare, Google, Quad9). Never used
/// implicitly: an operator who wants them passes them to [`UdpResolver::new`],
/// knowing the queried domain names then go to a third party.
pub const PUBLIC_RESOLVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];

pub fn public_resolvers() -> Vec<SocketAddr> {
    PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// EDNS(0) UDP payload size we advertise (the DNS flag day 2020 value).
const EDNS_PAYLOAD: u16 = 1232;
/// Receive buffer; larger than advertised in case a server ignores EDNS.
const MAX_MESSAGE: usize = 4096;
/// Records read from one answer section.
const MAX_ANSWERS: usize = 64;
/// Compression pointers followed in one name.
const MAX_POINTERS: usize = 16;

/// A dependency-free stub resolver: one UDP query per server, in order, until
/// one answers. Truncated answers are reported as failures (no TCP fallback).
/// Honours [`NetworkGuard`]: offline, no socket is opened.
#[derive(Debug, Clone)]
pub struct UdpResolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    guard: NetworkGuard,
}

impl UdpResolver {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

    /// Query `servers` in order, waiting `timeout` for each.
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration, guard: NetworkGuard) -> Self {
        Self {
            servers,
            timeout,
            guard,
        }
    }

    /// The system resolvers from `/etc/resolv.conf` (Unix). With none found,
    /// every lookup fails; there is no silent public fallback.
    pub fn system(timeout: Duration, guard: NetworkGuard) -> Self {
        #[cfg(unix)]
        let servers = std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| parse_resolv_conf(&text))
            .unwrap_or_default();
        #[cfg(not(unix))]
        let servers = vec![];
        Self::new(servers, timeout, guard)
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    async fn ask(
        &self,
        server: SocketAddr,
        packet: &[u8],
        id: u16,
        name: &str,
        kind: RecordType,
    ) -> Result<Vec<String>, DnsError> {
        let io = |e: std::io::Error| DnsError::Failed(format!("{server}: {e}"));
        let local: SocketAddr = if server.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = tokio::net::UdpSocket::bind(local).await.map_err(io)?;
        // A connected socket only receives datagrams from `server`.
        socket.connect(server).await.map_err(io)?;
        socket.send(packet).await.map_err(io)?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            let n = tokio::time::timeout_at(deadline, socket.recv(&mut buf))
                .await
                .map_err(|_| DnsError::Failed(format!("{server}: timed out")))?
                .map_err(io)?;
            // Ignore stray datagrams for other queries.
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return parse_response(&buf[..n], id, name, kind);
            }
        }
    }
}

impl Resolver for UdpResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            if self.guard == NetworkGuard::Offline {
                return Err(DnsError::Failed(format!(
                    "network disabled ({OFFLINE_ENV} is set)"
                )));
            }
            if self.servers.is_empty() {
                return Err(DnsError::Failed("no DNS servers configured".into()));
            }
            let mut id = [0u8; 2];
            getrandom::fill(&mut id)
                .map_err(|e| DnsError::Failed(format!("random query id: {e}")))?;
            let id = u16::from_be_bytes(id);
            let packet = encode_query(id, name, kind)?;
            let mut last = String::new();
            for server in &self.servers {
                match self.ask(*server, &packet, id, name, kind).await {
                    Err(DnsError::Failed(e)) => last = e,
                    answer => return answer,
                }
            }
            Err(DnsError::Failed(last))
        })
    }
}

/// The resolver for live runs: `servers` (IP or IP:port, port 53 by default)
/// or, when empty, the system resolvers from `/etc/resolv.conf`. With
/// `JUNCTION_CHECK_OFFLINE` set, every lookup fails without opening a socket.
pub fn configured(servers: &[String]) -> anyhow::Result<std::sync::Arc<dyn Resolver>> {
    let guard = NetworkGuard::from_env();
    let resolver = if servers.is_empty() {
        UdpResolver::system(UdpResolver::DEFAULT_TIMEOUT, guard)
    } else {
        let servers = servers
            .iter()
            .map(|s| parse_server(s))
            .collect::<anyhow::Result<Vec<_>>>()?;
        UdpResolver::new(servers, UdpResolver::DEFAULT_TIMEOUT, guard)
    };
    Ok(std::sync::Arc::new(resolver))
}

/// `192.0.2.53`, `192.0.2.53:5353`, `2001:db8::53` or `[2001:db8::53]:53`.
pub fn parse_server(server: &str) -> anyhow::Result<SocketAddr> {
    let server = server.trim();
    server
        .parse::<SocketAddr>()
        .or_else(|_| server.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| anyhow::anyhow!("DNS server {server:?} is not an IP address or IP:port"))
}

/// `nameserver` addresses from resolv.conf text (at most three, like libc).
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver")
                .then(|| words.next())
                .flatten()
                .and_then(|a| a.parse::<IpAddr>().ok())
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .take(3)
        .collect()
}

fn invalid(name: &str) -> DnsError {
    DnsError::Failed(format!("{name:?} is not a valid DNS name"))
}

/// A recursive query for `name` with an EDNS(0) OPT record.
pub fn encode_query(id: u16, name: &str, kind: RecordType) -> Result<Vec<u8>, DnsError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(invalid(name));
    }
    let mut p = Vec::with_capacity(trimmed.len() + 29);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // QD=1 AN=0 NS=0 AR=1
    for label in trimmed.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(invalid(name));
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&kind.code().to_be_bytes());
    p.extend_from_slice(&[0, 1]); // IN
    // OPT: root owner, type 41, class = payload size, TTL and RDLENGTH zero.
    p.extend_from_slice(&[0, 0, 41]);
    p.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    Ok(p)
}

fn malformed(what: &str) -> DnsError {
    DnsError::Failed(format!("malformed DNS response: {what}"))
}

fn u16_at(msg: &[u8], pos: usize) -> Result<u16, DnsError> {
    msg.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| malformed("truncated field"))
}

/// Read a possibly compressed name at `start`. Returns the name ("." for the
/// root) and the offset just past it. Pointers must point backwards and are
/// bounded, so a crafted loop cannot hang the parser.
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut end = None;
    let mut pointers = 0;
    let mut wire_len = 0usize;
    let mut name = String::new();
    loop {
        let len = *msg.get(pos).ok_or_else(|| malformed("name past end"))? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => {
                end.get_or_insert(pos + 1);
                break;
            }
            0x00 => {
                let label = msg
                    .get(pos + 1..pos + 1 + len)
                    .ok_or_else(|| malformed("label past end"))?;
                wire_len += len + 1;
                if wire_len > 255 {
                    return Err(malformed("name too long"));
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    if b.is_ascii_graphic() && b != b'.' && b != b'\\' {
                        name.push(b as char);
                    } else {
                        name.push_str(&format!("\\{b:03}"));
                    }
                }
                pos += 1 + len;
            }
            0xC0 => {
                let target = (u16_at(msg, pos)? & 0x3FFF) as usize;
                pointers += 1;
                if pointers > MAX_POINTERS || target >= pos {
                    return Err(malformed("compression pointer loop"));
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(malformed("unsupported label type")),
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok((name, end.unwrap_or(pos)))
}

/// TXT RDATA: one or more length-prefixed strings, joined.
fn read_txt(rdata: &[u8]) -> Result<String, DnsError> {
    let mut out = Vec::with_capacity(rdata.len());
    let mut pos = 0;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        let part = rdata
            .get(pos + 1..pos + 1 + len)
            .ok_or_else(|| malformed("TXT string past end"))?;
        out.extend_from_slice(part);
        pos += 1 + len;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Parse a response to the query (`id`, `name`, `kind`): the records of that
/// type in the answer section. NXDOMAIN and empty answers are `NotFound`;
/// truncation, server errors and malformed packets are `Failed`.
pub fn parse_response(
    msg: &[u8],
    id: u16,
    name: &str,
    kind: RecordType,
) -> Result<Vec<String>, DnsError> {
    if msg.len() < 12 {
        return Err(malformed("short header"));
    }
    let flags = u16_at(msg, 2)?;
    if u16_at(msg, 0)? != id || flags & 0x8000 == 0 {
        return Err(malformed("not a response to this query"));
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError::Failed(
            "truncated response (TCP fallback is not supported)".into(),
        ));
    }
    match flags & 0x000F {
        0 => {}
        3 => return Err(DnsError::NotFound),
        2 => return Err(DnsError::Failed("server failure (SERVFAIL)".into())),
        5 => return Err(DnsError::Failed("query refused (REFUSED)".into())),
        code => return Err(DnsError::Failed(format!("server returned rcode {code}"))),
    }
    if u16_at(msg, 4)? != 1 {
        return Err(malformed("expected one question"));
    }
    let answers = u16_at(msg, 6)? as usize;
    let (qname, mut pos) = read_name(msg, 12)?;
    let wanted = name.strip_suffix('.').unwrap_or(name);
    if !qname.eq_ignore_ascii_case(wanted)
        || u16_at(msg, pos)? != kind.code()
        || u16_at(msg, pos + 2)? != 1
    {
        return Err(malformed("question does not match the query"));
    }
    pos += 4;
    let mut out = vec![];
    for _ in 0..answers.min(MAX_ANSWERS) {
        let (_, next) = read_name(msg, pos)?;
        let rtype = u16_at(msg, next)?;
        let class = u16_at(msg, next + 2)?;
        let rdlen = u16_at(msg, next + 8)? as usize;
        let start = next + 10;
        let rdata = msg
            .get(start..start + rdlen)
            .ok_or_else(|| malformed("record data past end"))?;
        if rtype == kind.code() && class == 1 {
            out.push(match kind {
                RecordType::Txt => read_txt(rdata)?,
                RecordType::Cname => {
                    let (target, end) = read_name(msg, start)?;
                    if end > start + rdlen {
                        return Err(malformed("CNAME past record data"));
                    }
                    target
                }
                RecordType::Mx => {
                    if rdlen < 3 {
                        return Err(malformed("short MX record"));
                    }
                    let (host, end) = read_name(msg, start + 2)?;
                    if end > start + rdlen {
                        return Err(malformed("MX past record data"));
                    }
                    host
                }
            });
        }
        pos = start + rdlen;
    }
    if out.is_empty() {
        Err(DnsError::NotFound)
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0xBEEF;

    /// A response header plus the question for `name`/`kind`; the question
    /// name starts at offset 12, so answers can point to it with `0xC0 0x0C`.
    fn response(flags: u16, answers: u16, name: &str, kind: RecordType) -> Vec<u8> {
        let mut m = ID.to_be_bytes().to_vec();
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m.extend_from_slice(&answers.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&kind.code().to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m
    }

    /// An answer owned by the question name (compressed) with `rdata`.
    fn answer(m: &mut Vec<u8>, kind: RecordType, rdata: &[u8]) {
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&kind.code().to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]);
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(rdata);
    }

    const OK: u16 = 0x8180;

    #[test]
    fn query_is_encoded_with_edns() {
        let q = encode_query(0x1234, "_dmarc.contoso.example.", RecordType::Txt).unwrap();
        assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..19], b"\x06_dmarc");
        assert_eq!(&q[q.len() - 15..q.len() - 11], &[0, 16, 0, 1]);
        assert_eq!(&q[q.len() - 11..], &[0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0]);
        for bad in ["", ".", "a..b", "space here.example", &"a".repeat(64)] {
            assert!(encode_query(1, bad, RecordType::Txt).is_err(), "{bad}");
        }
    }

    #[test]
    fn txt_strings_are_joined_per_record() {
        let mut m = response(OK, 2, "contoso.example", RecordType::Txt);
        answer(
            &mut m,
            RecordType::Txt,
            b"\x07v=spf1 \x27include:spf.protection.outlook.com -all",
        );
        answer(&mut m, RecordType::Txt, b"\x0bverify=1234");
        assert_eq!(
            parse_response(&m, ID, "Contoso.Example.", RecordType::Txt).unwrap(),
            [
                "v=spf1 include:spf.protection.outlook.com -all",
                "verify=1234"
            ]
        );
    }

    #[test]
    fn cname_and_mx_targets_follow_compression() {
        let name = "selector1._domainkey.contoso.example";
        let mut m = response(OK, 1, name, RecordType::Cname);
        // "selector1-contoso" + pointer to "contoso.example" inside the question (offset 12 + 21).
        let mut rdata = b"\x11selector1-contoso".to_vec();
        rdata.extend_from_slice(&[0xC0, 12 + 21]);
        answer(&mut m, RecordType::Cname, &rdata);
        assert_eq!(
            parse_response(&m, ID, name, RecordType::Cname).unwrap(),
            ["selector1-contoso.contoso.example"]
        );

        let mut m = response(OK, 2, "contoso.example", RecordType::Mx);
        answer(
            &mut m,
            RecordType::Mx,
            &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12],
        );
        answer(&mut m, RecordType::Mx, &[0, 0, 0]);
        assert_eq!(
            parse_response(&m, ID, "contoso.example", RecordType::Mx).unwrap(),
            ["mail.contoso.example", "."]
        );
    }

    #[test]
    fn other_record_types_are_skipped() {
        let mut m = response(OK, 2, "contoso.example", RecordType::Txt);
        answer(&mut m, RecordType::Cname, &[0xC0, 12]);
        answer(&mut m, RecordType::Txt, b"\x02ok");
        assert_eq!(
            parse_response(&m, ID, "contoso.example", RecordType::Txt).unwrap(),
            ["ok"]
        );
    }

    #[test]
    fn rcodes_and_empty_answers() {
        let nx = response(0x8183, 0, "contoso.example", RecordType::Txt);
        assert_eq!(
            parse_response(&nx, ID, "contoso.example", RecordType::Txt),
            Err(DnsError::NotFound)
        );
        let empty = response(OK, 0, "contoso.example", RecordType::Txt);
        assert_eq!(
            parse_response(&empty, ID, "contoso.example", RecordType::Txt),
            Err(DnsError::NotFound)
        );
        let servfail = response(0x8182, 0, "contoso.example", RecordType::Txt);
        assert!(matches!(
            parse_response(&servfail, ID, "contoso.example", RecordType::Txt),
            Err(DnsError::Failed(e)) if e.contains("SERVFAIL")
        ));
    }

    #[test]
    fn truncated_responses_fail() {
        let mut m = response(OK | 0x0200, 1, "contoso.example", RecordType::Txt);
        answer(&mut m, RecordType::Txt, b"\x02ok");
        assert!(matches!(
            parse_response(&m, ID, "contoso.example", RecordType::Txt),
            Err(DnsError::Failed(e)) if e.contains("truncated")
        ));
    }

    #[test]
    fn mismatched_responses_fail() {
        let m = response(OK, 0, "contoso.example", RecordType::Txt);
        assert!(parse_response(&m, ID + 1, "contoso.example", RecordType::Txt).is_err());
        assert!(parse_response(&m, ID, "fabrikam.example", RecordType::Txt).is_err());
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Mx).is_err());
        let query = encode_query(ID, "contoso.example", RecordType::Txt).unwrap();
        assert!(parse_response(&query, ID, "contoso.example", RecordType::Txt).is_err());
    }

    #[test]
    fn hostile_packets_fail_without_panicking() {
        // Pointer to itself.
        let mut m = response(OK, 1, "contoso.example", RecordType::Cname);
        let at = m.len() + 12;
        answer(&mut m, RecordType::Cname, &[0xC0, at as u8]);
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Cname).is_err());
        // Forward pointer.
        let mut m = response(OK, 1, "contoso.example", RecordType::Cname);
        answer(&mut m, RecordType::Cname, &[0xC0, 0xFF]);
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Cname).is_err());
        // RDLENGTH past the end.
        let mut m = response(OK, 1, "contoso.example", RecordType::Txt);
        answer(&mut m, RecordType::Txt, b"\x02ok");
        let len = m.len();
        m[len - 4] = 0x40;
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Txt).is_err());
        // TXT string longer than its record.
        let mut m = response(OK, 1, "contoso.example", RecordType::Txt);
        answer(&mut m, RecordType::Txt, b"\x09ok");
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Txt).is_err());
        // More answers announced than present.
        let m = response(OK, 5, "contoso.example", RecordType::Txt);
        assert!(parse_response(&m, ID, "contoso.example", RecordType::Txt).is_err());
        // Every truncation of a valid packet.
        let mut m = response(OK, 1, "contoso.example", RecordType::Mx);
        answer(
            &mut m,
            RecordType::Mx,
            &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12],
        );
        for n in 0..m.len() {
            let _ = parse_response(&m[..n], ID, "contoso.example", RecordType::Mx);
        }
    }

    #[test]
    fn resolv_conf_nameservers() {
        let text = "# comment\nsearch contoso.example\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nnameserver fe80::1%en0\nnameserver 192.0.2.54\nnameserver 192.0.2.55\n";
        assert_eq!(
            parse_resolv_conf(text),
            [
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
                "192.0.2.54:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn servers_parse_with_default_port() {
        assert_eq!(
            parse_server("192.0.2.53").unwrap(),
            "192.0.2.53:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(parse_server(" 192.0.2.53:5353 ").unwrap().port(), 5353);
        assert_eq!(parse_server("2001:db8::53").unwrap().port(), 53);
        assert_eq!(parse_server("[2001:db8::53]:54").unwrap().port(), 54);
        assert!(parse_server("dns.contoso.example").is_err());
        assert!(configured(&["not an address".into()]).is_err());
        assert!(configured(&["192.0.2.53".into()]).is_ok());
    }

    #[tokio::test]
    async fn offline_guard_and_missing_servers_fail_without_a_socket() {
        let offline = UdpResolver::new(
            public_resolvers(),
            Duration::from_secs(1),
            NetworkGuard::Offline,
        );
        assert!(matches!(
            offline.lookup("contoso.example", RecordType::Txt).await,
            Err(DnsError::Failed(e)) if e.contains(OFFLINE_ENV)
        ));
        let none = UdpResolver::new(vec![], Duration::from_secs(1), NetworkGuard::Allowed);
        assert!(matches!(
            none.lookup("contoso.example", RecordType::Txt).await,
            Err(DnsError::Failed(e)) if e.contains("no DNS servers")
        ));
    }

    #[tokio::test]
    async fn static_dns_failures() {
        let dns = StaticDns::new()
            .with("contoso.example", RecordType::Mx, &["mail.contoso.example"])
            .failing("contoso.example", RecordType::Txt);
        assert!(dns.lookup("CONTOSO.example", RecordType::Mx).await.is_ok());
        assert!(matches!(
            dns.lookup("contoso.example", RecordType::Txt).await,
            Err(DnsError::Failed(_))
        ));
        assert_eq!(
            dns.lookup("contoso.example", RecordType::Cname).await,
            Err(DnsError::NotFound)
        );
    }
}
