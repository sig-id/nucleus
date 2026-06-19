//! Minimal host-side credential broker for Nucleus broker egress.
//!
//! This is intentionally small and dependency-free. It is a reference for the
//! broker boundary, not a production proxy:
//!
//! - CONNECT requests are audited and tunneled, but their TLS payload is opaque,
//!   so this broker cannot inject an upstream Authorization header into CONNECT
//!   traffic without terminating TLS.
//! - Absolute-form HTTP requests such as `GET http://api.example/v1 HTTP/1.1`
//!   are forwarded with `Authorization: Bearer $BROKER_UPSTREAM_BEARER_TOKEN`.
//! - Set `BROKER_CLIENT_TOKEN` to require the sandbox to present a per-container
//!   token in `Proxy-Authorization: Bearer ...`,
//!   `Authorization: Bearer ...`, or `X-Nucleus-Credential-Broker-Token: ...`.
//!
//! Run on the host:
//!
//! ```text
//! BROKER_UPSTREAM_BEARER_TOKEN=provider-secret \
//! BROKER_ALLOWED_HOST=api.example.com:80 \
//! BROKER_CLIENT_TOKEN=<NUCLEUS_CREDENTIAL_BROKER_TOKEN from workload> \
//! cargo run --example credential_broker -- 0.0.0.0:8080
//! ```
//!
//! Start Nucleus with `--credential-broker 10.0.42.1:8080`. Binding the broker to
//! `0.0.0.0:8080` lets it accept connections that arrive on the bridge gateway.

use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_HEADER_BYTES: usize = 64 * 1024;

fn main() -> io::Result<()> {
    let listen = env::args()
        .nth(1)
        .or_else(|| env::var("BROKER_LISTEN").ok())
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let upstream_token = env::var("BROKER_UPSTREAM_BEARER_TOKEN").unwrap_or_default();
    let client_token = env::var("BROKER_CLIENT_TOKEN").ok();
    let allowed_host = env::var("BROKER_ALLOWED_HOST").ok();

    let listener = TcpListener::bind(&listen)?;
    eprintln!("credential broker listening on {}", listen);

    for accepted in listener.incoming() {
        match accepted {
            Ok(stream) => {
                let upstream_token = upstream_token.clone();
                let client_token = client_token.clone();
                let allowed_host = allowed_host.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(
                        stream,
                        &upstream_token,
                        client_token.as_deref(),
                        allowed_host.as_deref(),
                    ) {
                        eprintln!("broker_error error={}", err);
                    }
                });
            }
            Err(err) => eprintln!("accept_error error={}", err),
        }
    }

    Ok(())
}

fn handle_client(
    mut client: TcpStream,
    upstream_token: &str,
    client_token: Option<&str>,
    allowed_host: Option<&str>,
) -> io::Result<()> {
    let peer = client.peer_addr().ok();
    let header = read_http_header(&mut client)?;
    let request = String::from_utf8_lossy(&header);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or("HTTP/1.1");

    if !authorized(&request, client_token) {
        audit("deny_auth", peer, method, target, 407);
        client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        if !host_allowed(target, allowed_host) {
            audit("deny_host", peer, method, target, 403);
            client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
        let upstream = TcpStream::connect(target)?;
        audit("connect", peer, method, target, 200);
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        return tunnel(client, upstream);
    }

    let Some((host, path)) = parse_absolute_http_target(target) else {
        audit("deny_target", peer, method, target, 400);
        client.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    };

    if !host_allowed(&host, allowed_host) {
        audit("deny_host", peer, method, &host, 403);
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    if upstream_token.is_empty() {
        audit("deny_config", peer, method, &host, 500);
        client.write_all(
            b"HTTP/1.1 500 Broker Missing Upstream Token\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }

    let mut upstream = TcpStream::connect(&host)?;
    let rewritten = rewrite_http_request(&request, method, &path, version, &host, upstream_token);
    upstream.write_all(rewritten.as_bytes())?;
    audit("http_forward", peer, method, &host, 200);
    tunnel(client, upstream)
}

fn read_http_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = Vec::new();
    let mut buf = [0u8; 1];
    while header.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        header.push(buf[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP header was empty or too large",
    ))
}

fn authorized(request: &str, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    for line in request.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Authorization")
        {
            if value == format!("Bearer {}", expected) {
                return true;
            }
        }
        if name.eq_ignore_ascii_case("X-Nucleus-Credential-Broker-Token") && value == expected {
            return true;
        }
    }
    false
}

fn host_allowed(host: &str, allowed_host: Option<&str>) -> bool {
    allowed_host.map_or(true, |allowed| host.eq_ignore_ascii_case(allowed))
}

fn parse_absolute_http_target(target: &str) -> Option<(String, String)> {
    let rest = target.strip_prefix("http://")?;
    let (host, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{}", path)),
        None => (rest, "/".to_string()),
    };
    if host.is_empty() {
        None
    } else if host.contains(':') {
        Some((host.to_string(), path))
    } else {
        Some((format!("{}:80", host), path))
    }
}

fn rewrite_http_request(
    request: &str,
    method: &str,
    path: &str,
    version: &str,
    host: &str,
    upstream_token: &str,
) -> String {
    let mut out = format!("{} {} {}\r\n", method, path, version);
    let mut saw_host = false;
    for line in request.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Authorization")
            || name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("Host") {
            saw_host = true;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !saw_host {
        out.push_str("Host: ");
        out.push_str(host);
        out.push_str("\r\n");
    }
    out.push_str("Authorization: Bearer ");
    out.push_str(upstream_token);
    out.push_str("\r\nConnection: close\r\n\r\n");
    out
}

fn tunnel(left: TcpStream, right: TcpStream) -> io::Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_reader = right.try_clone()?;
    let mut left_writer = left;
    let mut right_writer = right;

    let upload = thread::spawn(move || copy_and_shutdown(&mut left_reader, &mut right_writer));
    let download = thread::spawn(move || copy_and_shutdown(&mut right_reader, &mut left_writer));

    let upload_result = upload.join().unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "upload thread panicked",
        ))
    });
    let download_result = download.join().unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "download thread panicked",
        ))
    });

    upload_result?;
    download_result?;
    Ok(())
}

fn copy_and_shutdown(reader: &mut TcpStream, writer: &mut TcpStream) -> io::Result<u64> {
    let result = io::copy(reader, writer);
    let _ = writer.shutdown(Shutdown::Write);
    result
}

fn audit(event: &str, peer: Option<std::net::SocketAddr>, method: &str, target: &str, status: u16) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    eprintln!(
        "broker_audit ts={} event={} peer={} method={} target={} status={}",
        ts,
        event,
        peer.map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string()),
        method,
        target,
        status
    );
}
