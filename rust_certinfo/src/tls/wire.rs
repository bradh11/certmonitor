// rust_certinfo/src/tls/wire.rs
//
// Deadline-bounded socket helpers shared by the plaintext exchanges the
// probe runs before its ClientHello: proxy tunnels and STARTTLS preambles.
// `what` names the exchange in error messages ("STARTTLS negotiation",
// "proxy negotiation") so a failure says which step gave up.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

pub(crate) const LINE_LIMIT: usize = 4096;

/// Set both socket timeouts to whatever is left before `deadline`.
pub(crate) fn arm(stream: &mut TcpStream, deadline: Instant, what: &str) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(format!("deadline elapsed during {what}"));
    }
    // macOS answers EINVAL when the peer has already closed the socket, so a
    // failure here means the connection is gone, not that the deadline is bad.
    stream
        .set_read_timeout(Some(left))
        .and_then(|_| stream.set_write_timeout(Some(left)))
        .map_err(|e| format!("connection closed during {what} ({e})"))
}

pub(crate) fn send(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
    what: &str,
) -> Result<(), String> {
    arm(stream, deadline, what)?;
    stream
        .write_all(bytes)
        .map_err(|e| format!("send failed during {what}: {e}"))
}

pub(crate) fn read_exact(
    stream: &mut TcpStream,
    size: usize,
    deadline: Instant,
    what: &str,
) -> Result<Vec<u8>, String> {
    let mut data = vec![0u8; size];
    let mut filled = 0;
    while filled < size {
        arm(stream, deadline, what)?;
        match stream.read(&mut data[filled..]) {
            Ok(0) => return Err(format!("connection closed during {what}")),
            Ok(n) => filled += n,
            Err(e) => return Err(format!("read failed during {what}: {e}")),
        }
    }
    Ok(data)
}

/// Read one line byte by byte so nothing past it is consumed; CR/LF trimmed.
pub(crate) fn read_line(
    stream: &mut TcpStream,
    deadline: Instant,
    what: &str,
) -> Result<String, String> {
    let mut line: Vec<u8> = Vec::new();
    while !line.ends_with(b"\n") {
        let byte = read_exact(stream, 1, deadline, what)?;
        line.push(byte[0]);
        if line.len() > LINE_LIMIT {
            return Err(format!("reply line too long during {what}"));
        }
    }
    let text = String::from_utf8_lossy(&line);
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}
