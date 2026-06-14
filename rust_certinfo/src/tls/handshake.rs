// rust_certinfo/src/tls/handshake.rs
//
// TLS 1.3 handshake messages (RFC 8446 §4): a ClientHello byte builder
// with a realistic extension set, and a ServerHello / HelloRetryRequest
// parser that extracts exactly what the PQ probe needs — the negotiated
// (or requested) named group and the selected protocol version.
//
// No crypto: the probe never completes a handshake, derives keys, or
// decrypts anything. It sends one ClientHello, reads the ServerHello,
// and hangs up.

use crate::tls::TlsParseError;

pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

pub const TLS12: u16 = 0x0303;
pub const TLS13: u16 = 0x0304;

// Extension codepoints (IANA "TLS ExtensionType Values").
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

/// RFC 8446 §4.1.3: a ServerHello whose `random` equals this value
/// (SHA-256 of "HelloRetryRequest") *is* a HelloRetryRequest.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

// ---- ClientHello builder ----------------------------------------------------

/// Inputs for [`build_client_hello`]. The caller (the probe) decides the
/// randomness and key-share policy; this module only does the byte
/// layout.
pub struct ClientHelloParams<'a> {
    pub random: [u8; 32],
    /// Legacy session id (≤ 32 bytes) echoed by the server; real
    /// clients send a random 32-byte value for middlebox compatibility.
    pub session_id: &'a [u8],
    /// Hostname for the `server_name` extension. `None` omits the
    /// extension (RFC 6066 forbids IP literals in SNI).
    pub sni: Option<&'a str>,
    /// Named groups for `supported_groups`, most-preferred first.
    pub offered_groups: &'a [u16],
    /// `(group, key_exchange)` entries for `key_share`. Must be a
    /// subset of `offered_groups`, in the same preference order.
    pub key_shares: &'a [(u16, &'a [u8])],
    /// ALPN protocol names (e.g. `b"h2"`, `b"http/1.1"`); empty omits
    /// the extension.
    pub alpn: &'a [&'a [u8]],
}

/// Cipher suites every TLS 1.3 stack supports (RFC 8446 §9.1).
const CIPHER_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303];

/// Signature algorithms a typical 2026 browser offers. The probe never
/// verifies a signature; the list just has to look like a real client
/// so servers and middleboxes answer normally.
const SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
    0x0807, // ed25519
];

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, v: usize) {
    debug_assert!(v < 1 << 24);
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

/// Append one extension: id, u16 length, body.
fn push_extension(out: &mut Vec<u8>, id: u16, body: &[u8]) {
    push_u16(out, id);
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Build a ClientHello handshake message (including the 4-byte
/// handshake header, excluding record framing — see
/// [`crate::tls::records::write_record`]).
pub fn build_client_hello(p: &ClientHelloParams<'_>) -> Vec<u8> {
    debug_assert!(p.session_id.len() <= 32);
    let mut body = Vec::with_capacity(512);

    // legacy_version is frozen at TLS 1.2; the real version negotiation
    // happens in supported_versions (RFC 8446 §4.1.2).
    push_u16(&mut body, TLS12);
    body.extend_from_slice(&p.random);
    body.push(p.session_id.len() as u8);
    body.extend_from_slice(p.session_id);

    push_u16(&mut body, (CIPHER_SUITES.len() * 2) as u16);
    for &suite in CIPHER_SUITES {
        push_u16(&mut body, suite);
    }
    // legacy_compression_methods: null only.
    body.push(1);
    body.push(0);

    // Extensions, in the order a typical client emits them.
    let mut exts = Vec::with_capacity(384);

    if let Some(host) = p.sni {
        // ServerNameList { NameType host_name(0), HostName }
        let name = host.as_bytes();
        let mut sni = Vec::with_capacity(name.len() + 5);
        push_u16(&mut sni, (name.len() + 3) as u16); // server_name_list length
        sni.push(0); // name_type host_name
        push_u16(&mut sni, name.len() as u16);
        sni.extend_from_slice(name);
        push_extension(&mut exts, EXT_SERVER_NAME, &sni);
    }

    {
        let mut groups = Vec::with_capacity(p.offered_groups.len() * 2 + 2);
        push_u16(&mut groups, (p.offered_groups.len() * 2) as u16);
        for &g in p.offered_groups {
            push_u16(&mut groups, g);
        }
        push_extension(&mut exts, EXT_SUPPORTED_GROUPS, &groups);
    }

    {
        let mut sigs = Vec::with_capacity(SIGNATURE_ALGORITHMS.len() * 2 + 2);
        push_u16(&mut sigs, (SIGNATURE_ALGORITHMS.len() * 2) as u16);
        for &s in SIGNATURE_ALGORITHMS {
            push_u16(&mut sigs, s);
        }
        push_extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &sigs);
    }

    if !p.alpn.is_empty() {
        let mut alpn = Vec::new();
        let list_len: usize = p.alpn.iter().map(|n| n.len() + 1).sum();
        push_u16(&mut alpn, list_len as u16);
        for name in p.alpn {
            alpn.push(name.len() as u8);
            alpn.extend_from_slice(name);
        }
        push_extension(&mut exts, EXT_ALPN, &alpn);
    }

    {
        // Offer 1.3 first, then 1.2 so legacy servers still answer with
        // a parseable ServerHello instead of an alert.
        let versions = [TLS13, TLS12];
        let mut sv = Vec::with_capacity(versions.len() * 2 + 1);
        sv.push((versions.len() * 2) as u8);
        for &v in &versions {
            push_u16(&mut sv, v);
        }
        push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &sv);
    }

    {
        let entries_len: usize = p.key_shares.iter().map(|(_, kex)| kex.len() + 4).sum();
        let mut ks = Vec::with_capacity(entries_len + 2);
        push_u16(&mut ks, entries_len as u16);
        for (group, kex) in p.key_shares {
            push_u16(&mut ks, *group);
            push_u16(&mut ks, kex.len() as u16);
            ks.extend_from_slice(kex);
        }
        push_extension(&mut exts, EXT_KEY_SHARE, &ks);
    }

    push_u16(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    push_u24(&mut msg, body.len());
    msg.extend_from_slice(&body);
    msg
}

// ---- ServerHello / HelloRetryRequest parser ---------------------------------

/// What the probe learns from one ServerHello (or HelloRetryRequest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloSummary {
    /// True when `random` is the RFC 8446 §4.1.3 HRR magic. In that
    /// case `key_share_group` is the group the server *requests*, which
    /// is itself a capability signal.
    pub is_hello_retry_request: bool,
    pub legacy_version: u16,
    pub cipher_suite: u16,
    /// From the `supported_versions` extension. `None` on a server that
    /// negotiated TLS 1.2 or older (the extension is not echoed).
    pub selected_version: Option<u16>,
    /// The named group from the `key_share` extension: the negotiated
    /// group on a ServerHello, the requested group on an HRR.
    pub key_share_group: Option<u16>,
}

/// Bounds-checked byte cursor. Every read that would pass the end of
/// the buffer returns `Truncated`; nothing panics on adversarial input.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsParseError> {
        if self.remaining() < n {
            return Err(TlsParseError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TlsParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsParseError> {
        let b = self.take(2)?;
        Ok(u16::from(b[0]) << 8 | u16::from(b[1]))
    }

    fn u24(&mut self) -> Result<usize, TlsParseError> {
        let b = self.take(3)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
}

/// Parse a ServerHello handshake message (including the 4-byte
/// handshake header). Unknown extensions are skipped; structural
/// violations and truncation return errors, never panic.
pub fn parse_server_hello(msg: &[u8]) -> Result<ServerHelloSummary, TlsParseError> {
    let mut c = Cursor::new(msg);

    let msg_type = c.u8()?;
    if msg_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(TlsParseError::UnexpectedHandshakeType {
            expected: HANDSHAKE_TYPE_SERVER_HELLO,
            got: msg_type,
        });
    }
    let body_len = c.u24()?;
    if body_len != c.remaining() {
        // Reject both truncation and trailing garbage: the probe hands
        // us exactly one handshake message.
        return Err(TlsParseError::Truncated);
    }

    let legacy_version = c.u16()?;
    let random: &[u8] = c.take(32)?;
    let is_hello_retry_request = random == HELLO_RETRY_REQUEST_RANDOM;

    let session_id_len = usize::from(c.u8()?);
    if session_id_len > 32 {
        return Err(TlsParseError::Malformed("legacy_session_id_echo length"));
    }
    c.take(session_id_len)?;

    let cipher_suite = c.u16()?;
    let _compression = c.u8()?;

    let mut selected_version = None;
    let mut key_share_group = None;

    // Extensions block is optional in a strict TLS 1.2 ServerHello.
    if c.remaining() > 0 {
        let ext_block_len = usize::from(c.u16()?);
        if ext_block_len != c.remaining() {
            return Err(TlsParseError::Malformed("extensions length"));
        }
        while c.remaining() > 0 {
            let ext_id = c.u16()?;
            let ext_len = usize::from(c.u16()?);
            let ext_body = c.take(ext_len)?;
            let mut e = Cursor::new(ext_body);
            match ext_id {
                EXT_SUPPORTED_VERSIONS => {
                    // ServerHello form: one selected version.
                    selected_version = Some(e.u16()?);
                }
                EXT_KEY_SHARE => {
                    // ServerHello: KeyShareEntry { group, key_exchange }.
                    // HelloRetryRequest: bare NamedGroup the server wants.
                    let group = e.u16()?;
                    if !is_hello_retry_request {
                        let kex_len = usize::from(e.u16()?);
                        e.take(kex_len)?;
                    }
                    key_share_group = Some(group);
                }
                _ => {
                    // Unknown/unneeded extension — already consumed.
                }
            }
        }
    }

    Ok(ServerHelloSummary {
        is_hello_retry_request,
        legacy_version,
        cipher_suite,
        selected_version,
        key_share_group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- test builders ------------------------------------------------

    /// Synthesize a ServerHello. Live-captured fixtures (openssl s_client
    /// against real PQ/classical/legacy hosts) can be dropped into
    /// rust_certinfo/tests/fixtures/ later; the synthetic bytes follow
    /// RFC 8446 §4.1.3 exactly.
    fn build_server_hello(
        random: &[u8; 32],
        selected_version: Option<u16>,
        key_share: Option<(u16, &[u8])>,
        hrr_group: Option<u16>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        push_u16(&mut body, TLS12); // legacy_version is always 0x0303
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(&[0xAB; 32]); // legacy_session_id_echo
        push_u16(&mut body, 0x1301); // TLS_AES_128_GCM_SHA256
        body.push(0); // legacy_compression_method

        let mut exts = Vec::new();
        if let Some(v) = selected_version {
            let mut sv = Vec::new();
            push_u16(&mut sv, v);
            push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &sv);
        }
        if let Some((group, kex)) = key_share {
            let mut ks = Vec::new();
            push_u16(&mut ks, group);
            push_u16(&mut ks, kex.len() as u16);
            ks.extend_from_slice(kex);
            push_extension(&mut exts, EXT_KEY_SHARE, &ks);
        }
        if let Some(group) = hrr_group {
            let mut ks = Vec::new();
            push_u16(&mut ks, group);
            push_extension(&mut exts, EXT_KEY_SHARE, &ks);
        }
        push_u16(&mut body, exts.len() as u16);
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(HANDSHAKE_TYPE_SERVER_HELLO);
        push_u24(&mut msg, body.len());
        msg.extend_from_slice(&body);
        msg
    }

    fn probe_client_hello() -> Vec<u8> {
        build_client_hello(&ClientHelloParams {
            random: [0x42; 32],
            session_id: &[0x24; 32],
            sni: Some("example.com"),
            offered_groups: &[0x11EC, 0x001D, 0x0017],
            key_shares: &[(0x11EC, &[0xAA; 1216]), (0x001D, &[0xBB; 32])],
            alpn: &[b"h2", b"http/1.1"],
        })
    }

    // ---- ClientHello --------------------------------------------------

    #[test]
    fn client_hello_roundtrips_through_a_structural_walk() {
        let msg = probe_client_hello();
        let mut c = Cursor::new(&msg);
        assert_eq!(c.u8().unwrap(), HANDSHAKE_TYPE_CLIENT_HELLO);
        assert_eq!(c.u24().unwrap(), c.remaining());
        assert_eq!(c.u16().unwrap(), TLS12); // legacy_version
        assert_eq!(c.take(32).unwrap(), &[0x42; 32]);
        let sid_len = usize::from(c.u8().unwrap());
        assert_eq!(sid_len, 32);
        c.take(sid_len).unwrap();
        let suites_len = usize::from(c.u16().unwrap());
        assert_eq!(suites_len, CIPHER_SUITES.len() * 2);
        c.take(suites_len).unwrap();
        assert_eq!(c.u8().unwrap(), 1); // one compression method
        assert_eq!(c.u8().unwrap(), 0); // null

        let ext_len = usize::from(c.u16().unwrap());
        assert_eq!(ext_len, c.remaining());

        // Walk every extension and collect what a server would see.
        let mut seen = Vec::new();
        let mut groups = Vec::new();
        let mut share_groups = Vec::new();
        let mut versions = Vec::new();
        let mut sni = None;
        while c.remaining() > 0 {
            let id = c.u16().unwrap();
            let len = usize::from(c.u16().unwrap());
            let body = c.take(len).unwrap();
            seen.push(id);
            let mut e = Cursor::new(body);
            match id {
                EXT_SERVER_NAME => {
                    e.u16().unwrap(); // list length
                    assert_eq!(e.u8().unwrap(), 0); // host_name
                    let n = usize::from(e.u16().unwrap());
                    sni = Some(e.take(n).unwrap().to_vec());
                }
                EXT_SUPPORTED_GROUPS => {
                    let n = usize::from(e.u16().unwrap());
                    for _ in 0..n / 2 {
                        groups.push(e.u16().unwrap());
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let n = usize::from(e.u8().unwrap());
                    for _ in 0..n / 2 {
                        versions.push(e.u16().unwrap());
                    }
                }
                EXT_KEY_SHARE => {
                    let n = usize::from(e.u16().unwrap());
                    let mut inner = Cursor::new(e.take(n).unwrap());
                    while inner.remaining() > 0 {
                        let g = inner.u16().unwrap();
                        let kl = usize::from(inner.u16().unwrap());
                        inner.take(kl).unwrap();
                        share_groups.push(g);
                    }
                }
                _ => {}
            }
        }

        assert_eq!(sni.as_deref(), Some(b"example.com".as_ref()));
        assert_eq!(groups, vec![0x11EC, 0x001D, 0x0017]);
        assert_eq!(share_groups, vec![0x11EC, 0x001D]);
        assert!(versions.contains(&TLS13));
        assert!(seen.contains(&EXT_SIGNATURE_ALGORITHMS));
        assert!(seen.contains(&EXT_ALPN));
    }

    #[test]
    fn client_hello_omits_sni_and_alpn_when_absent() {
        let msg = build_client_hello(&ClientHelloParams {
            random: [0; 32],
            session_id: &[],
            sni: None,
            offered_groups: &[0x001D],
            key_shares: &[(0x001D, &[0xBB; 32])],
            alpn: &[],
        });
        // Walk extensions; server_name (0) and ALPN (16) must not appear.
        let mut c = Cursor::new(&msg);
        c.u8().unwrap();
        c.u24().unwrap();
        c.u16().unwrap();
        c.take(32).unwrap();
        let sid = usize::from(c.u8().unwrap());
        c.take(sid).unwrap();
        let suites = usize::from(c.u16().unwrap());
        c.take(suites).unwrap();
        c.u8().unwrap();
        c.u8().unwrap();
        c.u16().unwrap();
        while c.remaining() > 0 {
            let id = c.u16().unwrap();
            let len = usize::from(c.u16().unwrap());
            c.take(len).unwrap();
            assert_ne!(id, EXT_SERVER_NAME);
            assert_ne!(id, EXT_ALPN);
        }
    }

    // ---- ServerHello ---------------------------------------------------

    #[test]
    fn tls13_hybrid_pq_server_hello() {
        let msg = build_server_hello(
            &[0x55; 32],
            Some(TLS13),
            Some((0x11EC, &[0xCC; 1120])),
            None,
        );
        let summary = parse_server_hello(&msg).unwrap();
        assert!(!summary.is_hello_retry_request);
        assert_eq!(summary.legacy_version, TLS12);
        assert_eq!(summary.cipher_suite, 0x1301);
        assert_eq!(summary.selected_version, Some(TLS13));
        assert_eq!(summary.key_share_group, Some(0x11EC));
    }

    #[test]
    fn tls13_classical_server_hello() {
        let msg = build_server_hello(&[0x55; 32], Some(TLS13), Some((0x001D, &[0xCC; 32])), None);
        let summary = parse_server_hello(&msg).unwrap();
        assert_eq!(summary.key_share_group, Some(0x001D));
    }

    #[test]
    fn tls12_server_hello_has_no_selected_version() {
        // A TLS 1.2 server echoes neither supported_versions nor
        // key_share — the degradation signal the probe relies on.
        let msg = build_server_hello(&[0x55; 32], None, None, None);
        let summary = parse_server_hello(&msg).unwrap();
        assert_eq!(summary.selected_version, None);
        assert_eq!(summary.key_share_group, None);
        assert!(!summary.is_hello_retry_request);
    }

    #[test]
    fn hello_retry_request_carries_requested_group() {
        let msg = build_server_hello(&HELLO_RETRY_REQUEST_RANDOM, Some(TLS13), None, Some(0x11EC));
        let summary = parse_server_hello(&msg).unwrap();
        assert!(summary.is_hello_retry_request);
        // The requested group is itself a capability signal (#34).
        assert_eq!(summary.key_share_group, Some(0x11EC));
        assert_eq!(summary.selected_version, Some(TLS13));
    }

    #[test]
    fn wrong_handshake_type_rejected() {
        let mut msg = build_server_hello(&[0x55; 32], Some(TLS13), None, None);
        msg[0] = HANDSHAKE_TYPE_CLIENT_HELLO;
        assert_eq!(
            parse_server_hello(&msg),
            Err(TlsParseError::UnexpectedHandshakeType {
                expected: HANDSHAKE_TYPE_SERVER_HELLO,
                got: HANDSHAKE_TYPE_CLIENT_HELLO,
            })
        );
    }

    #[test]
    fn every_truncation_errors_instead_of_panicking() {
        let msg = build_server_hello(
            &[0x55; 32],
            Some(TLS13),
            Some((0x11EC, &[0xCC; 1120])),
            None,
        );
        for n in 0..msg.len() {
            assert!(
                parse_server_hello(&msg[..n]).is_err(),
                "truncation at {} bytes must error",
                n
            );
        }
    }

    #[test]
    fn oversized_session_id_rejected() {
        let mut msg = build_server_hello(&[0x55; 32], Some(TLS13), None, None);
        // Byte 38 (after type+len+version+random) is session_id length.
        msg[4 + 2 + 32] = 33;
        assert_eq!(
            parse_server_hello(&msg),
            Err(TlsParseError::Malformed("legacy_session_id_echo length"))
        );
    }

    #[test]
    fn lying_extension_block_length_rejected() {
        let mut msg = build_server_hello(&[0x55; 32], Some(TLS13), None, None);
        // Corrupt the extensions-block length (2 bytes before the first
        // extension id; the block sits at the end of the message).
        let ext_block_len_pos = msg.len() - 2 - 2 - 2 - 2; // sv ext: id+len+body(2)
        msg[ext_block_len_pos] ^= 0x10;
        assert!(parse_server_hello(&msg).is_err());
    }

    #[test]
    fn unknown_extensions_are_skipped() {
        // Hand-build a ServerHello carrying an unknown extension before
        // the ones the parser cares about.
        let mut body = Vec::new();
        push_u16(&mut body, TLS12);
        body.extend_from_slice(&[0x55; 32]);
        body.push(0); // empty session id echo
        push_u16(&mut body, 0x1302);
        body.push(0);
        let mut exts = Vec::new();
        push_extension(&mut exts, 0xFFAA, &[1, 2, 3, 4]); // unknown
        let mut sv = Vec::new();
        push_u16(&mut sv, TLS13);
        push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &sv);
        push_u16(&mut body, exts.len() as u16);
        body.extend_from_slice(&exts);
        let mut msg = vec![HANDSHAKE_TYPE_SERVER_HELLO];
        push_u24(&mut msg, body.len());
        msg.extend_from_slice(&body);

        let summary = parse_server_hello(&msg).unwrap();
        assert_eq!(summary.selected_version, Some(TLS13));
        assert_eq!(summary.cipher_suite, 0x1302);
    }

    #[test]
    fn trailing_garbage_rejected() {
        let mut msg = build_server_hello(&[0x55; 32], Some(TLS13), None, None);
        msg.extend_from_slice(&[0xDE, 0xAD]);
        assert!(parse_server_hello(&msg).is_err());
    }
}
