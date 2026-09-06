// rust_certinfo/src/tls/starttls.rs
//
// STARTTLS preambles for the PQ probe, mirroring certmonitor/starttls.py:
// SMTP, IMAP, POP3, FTP, PostgreSQL, and LDAP. Each function drives an
// already-connected TcpStream through the plaintext exchange and returns
// once the server has agreed to start TLS, leaving the stream ready for
// the ClientHello. Line-oriented protocols are read one byte at a time so
// nothing past the server's final reply is consumed. Every read and write
// is bounded by the probe's deadline.

use std::net::TcpStream;
use std::time::Instant;

use crate::tls::wire;

pub const PROTOCOLS: [&str; 6] = ["smtp", "imap", "pop3", "ftp", "postgres", "ldap"];
const LDAP_STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";
const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// Run the STARTTLS preamble for `protocol`. The error string is the
/// server's reply where there is one.
pub fn negotiate(stream: &mut TcpStream, protocol: &str, deadline: Instant) -> Result<(), String> {
    match protocol {
        "smtp" => smtp(stream, deadline),
        "imap" => imap(stream, deadline),
        "pop3" => pop3(stream, deadline),
        "ftp" => ftp(stream, deadline),
        "postgres" => postgres(stream, deadline),
        "ldap" => ldap(stream, deadline),
        other => Err(format!(
            "unsupported STARTTLS protocol {other:?}; choose one of {}",
            PROTOCOLS.join(", ")
        )),
    }
}

// --- I/O helpers ---------------------------------------------------------------------

const WHAT: &str = "STARTTLS negotiation";

fn send(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    wire::send(stream, bytes, deadline, WHAT)
}

fn read_exact(stream: &mut TcpStream, size: usize, deadline: Instant) -> Result<Vec<u8>, String> {
    wire::read_exact(stream, size, deadline, WHAT)
}

fn read_line(stream: &mut TcpStream, deadline: Instant) -> Result<String, String> {
    wire::read_line(stream, deadline, WHAT)
}

/// SMTP/FTP style reply: `NNN-` lines continue, `NNN ` (or short) ends it.
fn read_reply(stream: &mut TcpStream, deadline: Instant) -> Result<(String, Vec<String>), String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(stream, deadline)?;
        let done = line.len() < 4 || line.as_bytes()[3] != b'-';
        lines.push(line);
        if done {
            let code = lines
                .last()
                .map(|l| l.chars().take(3).collect())
                .unwrap_or_default();
            return Ok((code, lines));
        }
    }
}

fn expect(
    stream: &mut TcpStream,
    code: &str,
    what: &str,
    deadline: Instant,
) -> Result<Vec<String>, String> {
    let (got, lines) = read_reply(stream, deadline)?;
    if got != code {
        let last = lines.last().cloned().unwrap_or_default();
        return Err(format!("{what}: expected {code}, server said {last:?}"));
    }
    Ok(lines)
}

fn after_prefix(line: &str, prefix_len: usize) -> String {
    line.get(prefix_len..).unwrap_or("").to_ascii_uppercase()
}

// --- protocols -------------------------------------------------------------------------

fn smtp(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    expect(stream, "220", "SMTP greeting", deadline)?;
    send(stream, b"EHLO certmonitor\r\n", deadline)?;
    let capabilities = expect(stream, "250", "SMTP EHLO", deadline)?;
    if !capabilities
        .iter()
        .any(|l| after_prefix(l, 4).starts_with("STARTTLS"))
    {
        return Err("SMTP server does not advertise STARTTLS".into());
    }
    send(stream, b"STARTTLS\r\n", deadline)?;
    expect(stream, "220", "SMTP STARTTLS", deadline)?;
    Ok(())
}

fn ftp(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    expect(stream, "220", "FTP greeting", deadline)?;
    send(stream, b"AUTH TLS\r\n", deadline)?;
    expect(stream, "234", "FTP AUTH TLS", deadline)?;
    Ok(())
}

fn imap(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    let greeting = read_line(stream, deadline)?;
    let upper = greeting.to_ascii_uppercase();
    if !upper.starts_with("* OK") && !upper.starts_with("* PREAUTH") {
        return Err(format!("IMAP greeting: server said {greeting:?}"));
    }
    send(stream, b"a001 STARTTLS\r\n", deadline)?;
    loop {
        let line = read_line(stream, deadline)?;
        if line.starts_with("a001 ") {
            if after_prefix(&line, 5).starts_with("OK") {
                return Ok(());
            }
            return Err(format!("IMAP STARTTLS: server said {line:?}"));
        }
    }
}

fn pop3(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    let greeting = read_line(stream, deadline)?;
    if !greeting.starts_with("+OK") {
        return Err(format!("POP3 greeting: server said {greeting:?}"));
    }
    send(stream, b"STLS\r\n", deadline)?;
    let reply = read_line(stream, deadline)?;
    if !reply.starts_with("+OK") {
        return Err(format!("POP3 STLS: server said {reply:?}"));
    }
    Ok(())
}

fn postgres(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    send(stream, &POSTGRES_SSL_REQUEST, deadline)?;
    let answer = read_exact(stream, 1, deadline)?;
    match answer[0] {
        b'S' => Ok(()),
        b'N' => Err("PostgreSQL server declined SSL".into()),
        other => Err(format!(
            "PostgreSQL SSLRequest: unexpected reply {:?}",
            other as char
        )),
    }
}

// --- LDAP (RFC 4511 StartTLS extended operation) --------------------------------------

fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(content);
    out
}

fn ber_read(data: &[u8], offset: usize) -> Result<(u8, &[u8], usize), String> {
    if offset + 2 > data.len() {
        return Err("LDAP reply truncated".into());
    }
    let tag = data[offset];
    let first = data[offset + 1];
    let mut cursor = offset + 2;
    let length = if first & 0x80 != 0 {
        let size = (first & 0x7f) as usize;
        if size == 0 || size > 4 || cursor + size > data.len() {
            return Err("LDAP reply has an unsupported length encoding".into());
        }
        let mut value = 0usize;
        for byte in &data[cursor..cursor + size] {
            value = (value << 8) | *byte as usize;
        }
        cursor += size;
        value
    } else {
        first as usize
    };
    if cursor + length > data.len() {
        return Err("LDAP reply truncated".into());
    }
    Ok((tag, &data[cursor..cursor + length], cursor + length))
}

pub fn ldap_starttls_request() -> Vec<u8> {
    let request_name = ber(0x80, LDAP_STARTTLS_OID);
    let extended_request = ber(0x77, &request_name);
    let mut body = ber(0x02, &[1]);
    body.extend_from_slice(&extended_request);
    ber(0x30, &body)
}

fn ldap(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    send(stream, &ldap_starttls_request(), deadline)?;
    let head = read_exact(stream, 2, deadline)?;
    if head[0] != 0x30 {
        return Err(format!(
            "LDAP reply: expected an LDAPMessage, got tag 0x{:02x}",
            head[0]
        ));
    }
    let length = if head[1] & 0x80 != 0 {
        let size = (head[1] & 0x7f) as usize;
        if size == 0 || size > 4 {
            return Err("LDAP reply has an unsupported length encoding".into());
        }
        read_exact(stream, size, deadline)?
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize)
    } else {
        head[1] as usize
    };
    let body = read_exact(stream, length, deadline)?;
    let (_, _message_id, offset) = ber_read(&body, 0)?;
    let (op_tag, op, _) = ber_read(&body, offset)?;
    if op_tag != 0x78 {
        return Err(format!(
            "LDAP reply: expected an ExtendedResponse, got tag 0x{op_tag:02x}"
        ));
    }
    let (_, result_code, offset) = ber_read(op, 0)?;
    let (_, _matched_dn, offset) = ber_read(op, offset)?;
    let (_, diagnostic, _) = ber_read(op, offset)?;
    let code = result_code
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | *b as usize);
    if code != 0 || result_code.is_empty() {
        let detail = String::from_utf8_lossy(diagnostic);
        let detail = if detail.is_empty() {
            format!("resultCode {code}")
        } else {
            detail.to_string()
        };
        return Err(format!("LDAP StartTLS refused: {detail}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn serve<F>(handler: F) -> u16
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handler(stream);
            }
        });
        port
    }

    fn connect(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).unwrap()
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn line(reader: &mut BufReader<TcpStream>) -> String {
        let mut s = String::new();
        reader.read_line(&mut s).unwrap();
        s
    }

    #[test]
    fn smtp_preamble_succeeds() {
        let port = serve(|mut s| {
            let mut r = BufReader::new(s.try_clone().unwrap());
            s.write_all(b"220 fake\r\n").unwrap();
            assert!(line(&mut r).starts_with("EHLO "));
            s.write_all(b"250-fake\r\n250-STARTTLS\r\n250 OK\r\n")
                .unwrap();
            assert_eq!(line(&mut r).trim(), "STARTTLS");
            s.write_all(b"220 go\r\n").unwrap();
        });
        assert_eq!(negotiate(&mut connect(port), "smtp", deadline()), Ok(()));
    }

    #[test]
    fn smtp_refusal_carries_the_reply() {
        let port = serve(|mut s| {
            let mut r = BufReader::new(s.try_clone().unwrap());
            s.write_all(b"220 fake\r\n").unwrap();
            line(&mut r);
            s.write_all(b"250 fake\r\n").unwrap();
        });
        let err = negotiate(&mut connect(port), "smtp", deadline()).unwrap_err();
        assert!(err.contains("does not advertise STARTTLS"), "{err}");
    }

    #[test]
    fn imap_pop3_ftp_preambles_succeed() {
        let imap_port = serve(|mut s| {
            let mut r = BufReader::new(s.try_clone().unwrap());
            s.write_all(b"* OK ready\r\n").unwrap();
            assert_eq!(line(&mut r).trim(), "a001 STARTTLS");
            s.write_all(b"* noise\r\na001 OK begin\r\n").unwrap();
        });
        assert_eq!(
            negotiate(&mut connect(imap_port), "imap", deadline()),
            Ok(())
        );
        let pop3_port = serve(|mut s| {
            let mut r = BufReader::new(s.try_clone().unwrap());
            s.write_all(b"+OK\r\n").unwrap();
            assert_eq!(line(&mut r).trim(), "STLS");
            s.write_all(b"+OK begin\r\n").unwrap();
        });
        assert_eq!(
            negotiate(&mut connect(pop3_port), "pop3", deadline()),
            Ok(())
        );
        let ftp_port = serve(|mut s| {
            let mut r = BufReader::new(s.try_clone().unwrap());
            s.write_all(b"220-hi\r\n220 fake\r\n").unwrap();
            assert_eq!(line(&mut r).trim(), "AUTH TLS");
            s.write_all(b"234 ok\r\n").unwrap();
        });
        assert_eq!(negotiate(&mut connect(ftp_port), "ftp", deadline()), Ok(()));
    }

    #[test]
    fn postgres_accepts_and_declines() {
        let ok_port = serve(|mut s| {
            let mut buf = [0u8; 8];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(buf, POSTGRES_SSL_REQUEST);
            s.write_all(b"S").unwrap();
        });
        assert_eq!(
            negotiate(&mut connect(ok_port), "postgres", deadline()),
            Ok(())
        );
        let no_port = serve(|mut s| {
            let mut buf = [0u8; 8];
            s.read_exact(&mut buf).unwrap();
            s.write_all(b"N").unwrap();
        });
        let err = negotiate(&mut connect(no_port), "postgres", deadline()).unwrap_err();
        assert!(err.contains("declined SSL"), "{err}");
    }

    #[test]
    fn ldap_request_bytes_and_replies() {
        let request = ldap_starttls_request();
        assert_eq!(&request[..2], &[0x30, 0x1d]);
        assert_eq!(&request[5..9], &[0x77, 0x18, 0x80, 0x16]);
        let ok_port = serve(|mut s| {
            let mut buf = vec![0u8; 31];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(buf, ldap_starttls_request());
            s.write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .unwrap();
        });
        assert_eq!(negotiate(&mut connect(ok_port), "ldap", deadline()), Ok(()));
        let refuse_port = serve(|mut s| {
            let mut buf = vec![0u8; 31];
            s.read_exact(&mut buf).unwrap();
            let mut reply = vec![
                0x30, 0x1d, 0x02, 0x01, 0x01, 0x78, 0x18, 0x0a, 0x01, 0x01, 0x04, 0x00, 0x04, 0x11,
            ];
            reply.extend_from_slice(b"TLS not supported");
            s.write_all(&reply).unwrap();
        });
        let err = negotiate(&mut connect(refuse_port), "ldap", deadline()).unwrap_err();
        assert!(err.contains("TLS not supported"), "{err}");
    }

    #[test]
    fn closed_connection_and_unknown_protocol_are_errors() {
        let port = serve(|mut s| {
            s.write_all(b"220 fake\r\n").unwrap();
        });
        let err = negotiate(&mut connect(port), "smtp", deadline()).unwrap_err();
        assert!(
            err.contains("connection closed") || err.contains("read failed"),
            "{err}"
        );
        let port = serve(|_s| {});
        let err = negotiate(&mut connect(port), "gopher", deadline()).unwrap_err();
        assert!(err.contains("unsupported STARTTLS protocol"), "{err}");
    }

    #[test]
    fn ber_long_form_round_trips() {
        let payload = vec![b'x'; 300];
        let encoded = ber(0x04, &payload);
        assert_eq!(&encoded[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let (tag, content, next) = ber_read(&encoded, 0).unwrap();
        assert_eq!((tag, content.len(), next), (0x04, 300, encoded.len()));
        assert!(ber_read(&[0x04], 0).is_err());
        assert!(ber_read(&[0x04, 0x80], 0).is_err());
        assert!(ber_read(&[0x04, 0x05, b'a'], 0).is_err());
    }
}
