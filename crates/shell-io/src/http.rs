//! Minimal blocking HTTP/1.1 client over [`std::net::TcpStream`] — enough to POST a body and read
//! a response, std-only. `http://` only: TLS is the platform shell's job (URLSession/OkHttp with
//! the OS trust store); this exists so E2E tests exercise REAL sockets, not stubs.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Refuse absurd response headers/bodies (this is a test/reference client, not a browser).
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// POST `body` to an `http://host[:port]/path` URL.
pub fn post(url: &str, body: &[u8]) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| format!("write: {e}"))?;

    // `Connection: close` ⇒ read to EOF, then split headers/body.
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err("response too large".into());
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    parse_response(&raw)
}

/// Split an `http://host[:port]/path` URL. Rejects other schemes explicitly.
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("unsupported scheme (TLS is the platform shell's job): {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port")?),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok((host, port, path.to_string()))
}

/// Parse `HTTP/1.x <status> ...\r\n<headers>\r\n\r\n<body>`.
fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = core::str::from_utf8(&raw[..header_end]).map_err(|_| "non-UTF8 headers")?;
    let status_line = head.lines().next().ok_or("empty response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("malformed status line")?;
    let mut content_type = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed response header".into());
        };
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() || value.contains(',') {
                return Err("ambiguous content-type header".into());
            }
            let base = value
                .split(';')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase)
                .ok_or("empty content-type header")?;
            content_type = Some(base);
        }
    }
    Ok(HttpResponse {
        status,
        content_type,
        body: raw[header_end + 4..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080/response").unwrap(),
            ("127.0.0.1".into(), 8080, "/response".into())
        );
        assert_eq!(
            parse_http_url("http://rp.example/cb").unwrap(),
            ("rp.example".into(), 80, "/cb".into())
        );
        assert_eq!(
            parse_http_url("http://rp.example").unwrap(),
            ("rp.example".into(), 80, "/".into())
        );
        // TLS is the platform's job — refuse, don't pretend.
        assert!(parse_http_url("https://rp.example/cb").is_err());
        assert!(parse_http_url("ftp://x/").is_err());
    }

    #[test]
    fn response_parsing() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 2\r\n\r\n{}",
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type.as_deref(), Some("application/json"));
        assert_eq!(response.body, b"{}");
        let response = parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap();
        assert_eq!(response.status, 404);
        assert!(response.body.is_empty());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-type: text/html\r\n\r\n{}"
        )
        .is_err());
        assert!(parse_response(b"garbage").is_err());
    }
}
