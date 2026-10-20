//! Shared L7 upstream-forwarding pipeline.
//!
//! Used by both the reverse-proxy path ([`crate::reverse`]) and the
//! TLS-intercept CONNECT path ([`crate::tls_intercept`]). The two callers
//! differ in how they parse the inbound request, look up the route, and
//! transform/inject credentials, but converge on the same wire-level
//! upstream operation:
//!
//! 1. Establish an upstream byte stream — direct TCP (with optional TLS)
//!    or chained CONNECT through an enterprise proxy (then TLS).
//! 2. Write the pre-built HTTP/1.1 request bytes, then the body: either
//!    bytes the caller holds, or bytes relayed from the inbound stream
//!    through a fixed window so a body is never held whole.
//! 3. Stream the response back into the inbound sink.
//! 4. Emit one L7 audit event with the response status, or with no status
//!    when the inbound body failed after the request head went upstream.
//!
//! ## Why pre-built request bytes
//!
//! Each caller has its own rules for header filtering, credential
//! injection, and path transformation. Asking this module to handle that
//! would mean smuggling all of that policy through a parameter struct.
//! Instead, the caller hands in finished bytes: a clean separation
//! between "build the request" and "speak it on the wire".

use crate::audit;
use crate::error::{ProxyError, Result};
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Timeout for upstream TCP connect (matches the historical reverse-proxy value).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_REWRITE_READ_TIMEOUT: Duration = Duration::from_secs(30);

const RELAY_WINDOW: usize = 64 * 1024;

/// Cap on trailer lines after the last chunk of a chunked request (DoS bound).
pub(crate) const MAX_CHUNK_TRAILER_LINES: usize = 64;

/// How the client framed its request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body bytes follow the header block.
    Empty,
    /// `Content-Length` with this many bytes.
    ContentLength(NonZeroU64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// A request body for [`forward_request`] to write after the request bytes.
/// No `Debug`: a buffered body can carry real credentials.
pub enum RequestBody<'a> {
    /// A body the caller already holds in full.
    Buffered(&'a [u8]),
    /// A body still arriving on the inbound stream in `framing`. `prefix`
    /// holds the bytes already read past the header block.
    Inbound {
        framing: BodyFraming,
        prefix: &'a [u8],
    },
}

impl RequestBody<'_> {
    /// The framing header line the upstream request needs for this body.
    pub fn framing_header(&self) -> Option<String> {
        match *self {
            Self::Buffered([])
            | Self::Inbound {
                framing: BodyFraming::Empty,
                ..
            } => None,
            Self::Buffered(bytes) => Some(format!("Content-Length: {}\r\n", bytes.len())),
            Self::Inbound {
                framing: BodyFraming::ContentLength(len),
                ..
            } => Some(format!("Content-Length: {len}\r\n")),
            Self::Inbound {
                framing: BodyFraming::Chunked,
                ..
            } => Some("Transfer-Encoding: chunked\r\n".to_string()),
        }
    }
}

/// Scheme of the upstream connection. `Http` is only legal for loopback
/// targets; the caller is responsible for enforcing that invariant
/// (`reverse.rs` does so via `validate_http_upstream_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

/// How the upstream byte stream is established.
pub enum UpstreamStrategy<'a> {
    /// Connect directly to one of `resolved_addrs` (DNS rebinding-safe:
    /// the addresses must already have been validated by the host filter).
    Direct { resolved_addrs: &'a [SocketAddr] },
    /// Chain a CONNECT through an enterprise proxy. `proxy_addr` is the
    /// `host:port` of the corporate proxy; `proxy_auth_header` is the literal
    /// value to send in `Proxy-Authorization` (e.g. `"Basic …"`), or `None`
    /// for unauthenticated proxies.
    ExternalProxy {
        proxy_addr: &'a str,
        proxy_auth_header: Option<&'a str>,
    },
}

/// Description of the upstream the caller wants to reach.
pub struct UpstreamSpec<'a> {
    pub scheme: UpstreamScheme,
    pub host: &'a str,
    pub port: u16,
    pub strategy: UpstreamStrategy<'a>,
    /// TLS connector to use for an `Https` scheme. Reverse-proxy callers
    /// pass either the route's per-route connector (custom CA / mTLS) or
    /// the shared default; intercept callers do the same.
    pub tls_connector: &'a TlsConnector,
}

/// Audit-emission context.
pub struct AuditCtx<'a> {
    pub log: Option<&'a audit::SharedAuditLog>,
    pub mode: audit::ProxyMode,
    pub event_ctx: audit::EventContext<'a>,
    /// Logical target string (route prefix for reverse, hostname for intercept).
    pub target: &'a str,
    pub method: &'a str,
    /// Path as it should appear in the audit log (the *inbound* path before
    /// any rewriting — e.g. `/v1/chat/completions`, not the upstream URL).
    pub path: &'a str,
}

/// Optional HTTP/1.1 response body rewrite hook.
///
/// Used for OAuth token capture, where the proxy must buffer a token endpoint
/// response, replace real token fields with phantoms, and only then release the
/// response to the sandboxed client.
pub type ResponseRewrite<'a> =
    &'a (dyn Fn(u16, &[(String, String)], &[u8]) -> Result<Vec<u8>> + Send + Sync);

/// Connect to the upstream, write `request_bytes + body`, stream the
/// response back into `inbound`, and emit the L7 audit event.
///
/// Returns the response status code (or 502 if the upstream sent something
/// unparseable). A [`RequestBody::Inbound`] body that ends early or is
/// malformed closes the upstream connection mid-request and yields
/// [`ProxyError::RequestBody`].
pub async fn forward_request<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: RequestBody<'_>,
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    forward_request_with_response_rewrite(inbound, request_bytes, body, upstream, audit, None).await
}

pub async fn forward_request_with_response_rewrite<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: RequestBody<'_>,
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
    response_rewrite: Option<ResponseRewrite<'_>>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = match upstream.scheme {
        UpstreamScheme::Https => {
            let mut tls_stream = open_https_upstream(&upstream).await?;
            exchange(
                &mut tls_stream,
                inbound,
                request_bytes,
                body,
                response_rewrite,
            )
            .await
        }
        UpstreamScheme::Http => {
            let mut tcp_stream = open_http_upstream(&upstream).await?;
            exchange(
                &mut tcp_stream,
                inbound,
                request_bytes,
                body,
                response_rewrite,
            )
            .await
        }
    };
    // The upstream stream is dropped by now, so a failed body never completes
    // there; the head with any injected credential already went out.
    let status = match &result {
        Ok(status) => Some(*status),
        Err(ProxyError::RequestBody(_)) => None,
        Err(_) => return result,
    };

    audit::log_l7_request(
        audit.log,
        audit.mode,
        &audit.event_ctx,
        audit.target,
        audit.method,
        audit.path,
        status,
    );
    result
}

async fn exchange<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    request: &[u8],
    body: RequestBody<'_>,
    response_rewrite: Option<ResponseRewrite<'_>>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    write_request(upstream, inbound, request, body).await?;
    stream_or_rewrite_response(upstream, inbound, response_rewrite).await
}

async fn stream_or_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    response_rewrite: Option<ResponseRewrite<'_>>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    match response_rewrite {
        Some(rewrite) => buffer_rewrite_response(upstream, inbound, rewrite).await,
        None => stream_response(upstream, inbound).await,
    }
}

/// Open an upstream HTTPS connection (Direct TLS or ExternalProxy + TLS).
pub(crate) async fn open_https_upstream(
    upstream: &UpstreamSpec<'_>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = open_tcp_upstream(upstream).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(upstream.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    upstream
        .tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: upstream.host.to_string(),
            reason: format!("TLS handshake failed: {}", e),
        })
}

/// Open an upstream HTTP (plain) connection. Caller has already validated
/// that this is a loopback target.
async fn open_http_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    open_tcp_upstream(upstream).await
}

/// Establish the TCP layer of the upstream connection (without TLS).
pub(crate) async fn open_tcp_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    match upstream.strategy {
        UpstreamStrategy::Direct { resolved_addrs } => {
            if resolved_addrs.is_empty() {
                // Same fail-closed contract as CONNECT (`connect.rs`): never
                // re-resolve the hostname. An empty slice means DNS failed or
                // was skipped, so a second lookup would bypass the link-local
                // metadata check already applied to `resolved_addrs`.
                Err(ProxyError::UpstreamConnect {
                    host: upstream.host.to_string(),
                    reason: "DNS resolution returned no addresses".to_string(),
                })
            } else {
                connect_to_resolved(resolved_addrs, upstream.host).await
            }
        }
        UpstreamStrategy::ExternalProxy {
            proxy_addr,
            proxy_auth_header,
        } => crate::external::connect_via_proxy(
            proxy_addr,
            upstream.host,
            upstream.port,
            proxy_auth_header,
        )
        .await
        .map_err(|e| match e {
            ProxyError::ExternalProxy(reason) => ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason,
            },
            other => other,
        }),
    }
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. Connecting to the IP
/// directly (not re-resolving the hostname) prevents DNS rebinding TOCTOU.
async fn connect_to_resolved(addrs: &[SocketAddr], host: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                debug!("Connect to {} failed: {}", addr, e);
                last_err = Some(e.to_string());
            }
            Err(_) => {
                debug!("Connect to {} timed out", addr);
                last_err = Some("connection timed out".to_string());
            }
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_string(),
        reason: last_err.unwrap_or_else(|| "no addresses to connect to".to_string()),
    })
}

async fn write_request<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    request: &[u8],
    body: RequestBody<'_>,
) -> Result<()>
where
    U: AsyncWrite + Unpin,
    I: AsyncRead + Unpin,
{
    upstream.write_all(request).await?;
    match body {
        RequestBody::Buffered(bytes) => upstream.write_all(bytes).await?,
        RequestBody::Inbound { framing, prefix } => {
            let mut client = prefix.chain(inbound);
            match framing {
                BodyFraming::Empty => {}
                BodyFraming::ContentLength(len) => {
                    relay_exact(&mut client, upstream, len.get(), &mut vec![0; RELAY_WINDOW])
                        .await?;
                }
                BodyFraming::Chunked => relay_chunks(BufReader::new(client), upstream).await?,
            }
        }
    }
    upstream.flush().await?;
    Ok(())
}

async fn relay_exact<R, U>(
    client: &mut R,
    upstream: &mut U,
    len: u64,
    window: &mut [u8],
) -> Result<()>
where
    R: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut remaining = len;
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(window.len(), |r| r.min(window.len()));
        let n = client
            .read(&mut window[..want])
            .await
            .map_err(|e| ProxyError::RequestBody(format!("read failed: {e}")))?;
        if n == 0 {
            return Err(ProxyError::RequestBody(
                "truncated request body".to_string(),
            ));
        }
        upstream.write_all(&window[..n]).await?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Re-frame each chunk so the upstream sees only framing this proxy wrote.
/// Chunk extensions and trailers are dropped.
async fn relay_chunks<R, U>(mut client: R, upstream: &mut U) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut window = vec![0; RELAY_WINDOW];
    loop {
        let size = read_chunk_size(&mut client).await?;
        if size == 0 {
            skip_chunk_trailers(&mut client).await?;
            upstream.write_all(b"0\r\n\r\n").await?;
            return Ok(());
        }
        upstream
            .write_all(format!("{size:x}\r\n").as_bytes())
            .await?;
        relay_exact(&mut client, upstream, size, &mut window).await?;
        read_chunk_end(&mut client).await?;
        upstream.write_all(b"\r\n").await?;
    }
}

/// Read one chunk-size line of a chunked request body. Zero marks the last
/// chunk.
pub(crate) async fn read_chunk_size<R>(reader: &mut R) -> Result<u64>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let n = crate::line_reader::read_line_limited_string(
        reader,
        &mut line,
        crate::line_reader::MAX_LINE_SIZE,
    )
    .await
    .map_err(|e| ProxyError::RequestBody(format!("chunk size line: {e}")))?;
    if n == 0 {
        return Err(ProxyError::RequestBody(
            "truncated chunked request".to_string(),
        ));
    }
    let size_text = line.trim_end().split(';').next().unwrap_or("");
    u64::from_str_radix(size_text.trim(), 16)
        .map_err(|_| ProxyError::RequestBody("invalid chunk size".to_string()))
}

/// Read the CRLF that ends a chunk's data.
pub(crate) async fn read_chunk_end<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .map_err(|e| ProxyError::RequestBody(format!("truncated chunked request body: {e}")))?;
    if crlf != *b"\r\n" {
        return Err(ProxyError::RequestBody(
            "malformed chunk data terminator".to_string(),
        ));
    }
    Ok(())
}

/// Read and discard the trailer section after the last chunk. More than
/// [`MAX_CHUNK_TRAILER_LINES`] lines is an error.
pub(crate) async fn skip_chunk_trailers<R>(reader: &mut R) -> Result<()>
where
    R: AsyncBufRead + Unpin,
{
    for _ in 0..=MAX_CHUNK_TRAILER_LINES {
        let mut trailer = String::new();
        let n = crate::line_reader::read_line_limited_string(
            reader,
            &mut trailer,
            crate::line_reader::MAX_LINE_SIZE,
        )
        .await
        .map_err(|e| ProxyError::RequestBody(format!("chunk trailer line: {e}")))?;
        if n == 0 {
            return Err(ProxyError::RequestBody(
                "truncated chunked request trailers".to_string(),
            ));
        }
        if trailer == "\r\n" || trailer == "\n" {
            return Ok(());
        }
    }
    Err(ProxyError::RequestBody(
        "too many chunked request trailers".to_string(),
    ))
}

/// Stream the upstream response back to the inbound sink.
///
/// Returns the HTTP status code parsed from the first chunk. Streams
/// chunked / SSE / HTTP-streaming bodies transparently because we never
/// buffer the body — each upstream read is mirrored to the inbound write.
async fn stream_response<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut status_code: u16 = 502;
    let mut first_chunk = true;

    loop {
        let n = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };

        if first_chunk {
            status_code = parse_response_status(&buf[..n]);
            first_chunk = false;
        }

        inbound.write_all(&buf[..n]).await?;
        inbound.flush().await?;
    }

    Ok(status_code)
}

/// Parse HTTP status code from the first response chunk.
///
/// Returns 502 when the response doesn't contain a valid status line.
fn parse_response_status(data: &[u8]) -> u16 {
    let line_end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    let first_line = &data[..line_end.min(64)];

    if let Ok(line) = std::str::from_utf8(first_line) {
        let mut parts = line.split_whitespace();
        if let Some(version) = parts.next()
            && version.starts_with("HTTP/")
            && let Some(code_str) = parts.next()
            && code_str.len() == 3
        {
            return code_str.parse().unwrap_or(502);
        }
    }
    502
}

const MAX_REWRITE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

async fn buffer_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    rewrite: ResponseRewrite<'_>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(UPSTREAM_REWRITE_READ_TIMEOUT, upstream.read(&mut buf))
            .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Upstream read error: {}", e);
                break;
            }
            Err(_) => {
                return Err(ProxyError::HttpParse(
                    "timed out reading response for OAuth capture rewrite".to_string(),
                ));
            }
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_REWRITE_RESPONSE_BYTES {
            return Err(ProxyError::HttpParse(
                "response too large for OAuth capture rewrite".to_string(),
            ));
        }
    }

    let rewritten = rewrite_http1_response(&raw, rewrite)?;
    let status = parse_response_status(&rewritten);
    inbound.write_all(&rewritten).await?;
    inbound.flush().await?;
    Ok(status)
}

fn rewrite_http1_response(raw: &[u8], rewrite: ResponseRewrite<'_>) -> Result<Vec<u8>> {
    let Some(header_end) = find_header_end(raw) else {
        return Err(ProxyError::HttpParse(
            "upstream response missing header terminator".to_string(),
        ));
    };
    let head = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let head_str = std::str::from_utf8(head).map_err(|_| {
        ProxyError::HttpParse("upstream response headers are not UTF-8".to_string())
    })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::HttpParse("upstream response missing status".to_string()))?;
    let status = parse_response_status(raw);
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_encoded = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim().to_string();
        let value_trimmed = value.trim().to_string();
        if name_trimmed.eq_ignore_ascii_case("transfer-encoding")
            && value_trimmed
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name_trimmed.eq_ignore_ascii_case("content-encoding") && !value_trimmed.is_empty() {
            content_encoded = true;
        }
        headers.push((name_trimmed, value_trimmed));
    }

    if chunked {
        body = decode_chunked_body(&body)?;
    }
    if content_encoded {
        return Err(ProxyError::HttpParse(
            "cannot safely rewrite or inspect content-encoded OAuth capture response".to_string(),
        ));
    }

    let rewritten_body = rewrite(status, &headers, &body)?;
    let mut out = Vec::new();
    out.extend_from_slice(status_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", rewritten_body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rewritten_body);
    Ok(out)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let Some(line_end_rel) = body[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        };
        let line_end = pos + line_end_rel;
        let size_line = std::str::from_utf8(&body[pos..line_end])
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| ProxyError::HttpParse("chunk size overflow".to_string()))?;
        if end + 2 > body.len() || &body[end..end + 2] != b"\r\n" {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        }
        out.extend_from_slice(&body[pos..end]);
        pos = end + 2;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_status_extracts_code() {
        assert_eq!(parse_response_status(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_response_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(parse_response_status(b"HTTP/1.1 502 Bad Gateway\r\n"), 502);
    }

    #[test]
    fn parse_response_status_handles_garbage() {
        assert_eq!(parse_response_status(b""), 502);
        assert_eq!(parse_response_status(b"garbage"), 502);
        assert_eq!(parse_response_status(b"NOT-HTTP 200 OK"), 502);
    }

    #[test]
    fn rewrite_http1_response_decodes_chunked_body_before_rewrite() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let rewritten = rewrite_http1_response(raw, &|_, _, body| {
            assert_eq!(body, br#"{"a":1}"#);
            Ok(br#"{"b":2}"#.to_vec())
        })
        .unwrap();

        let text = std::str::from_utf8(&rewritten).unwrap();
        assert!(text.contains("Content-Length: 7"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(text.ends_with(r#"{"b":2}"#));
    }

    #[tokio::test]
    async fn open_tcp_upstream_fails_closed_when_resolved_addrs_empty() {
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(config));
        let spec = UpstreamSpec {
            scheme: UpstreamScheme::Http,
            host: "does-not-resolve.invalid",
            port: 80,
            strategy: UpstreamStrategy::Direct {
                resolved_addrs: &[],
            },
            tls_connector: &connector,
        };
        let err = open_tcp_upstream(&spec).await.expect_err("empty addrs");
        match err {
            ProxyError::UpstreamConnect { host, reason } => {
                assert_eq!(host, "does-not-resolve.invalid");
                assert!(
                    reason.contains("DNS resolution returned no addresses"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected UpstreamConnect, got {other}"),
        }
    }

    #[test]
    fn rewrite_http1_response_rejects_content_encoded_body_for_all_statuses() {
        let raw =
            b"HTTP/1.1 400 Bad Request\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nxxxx";
        let err = rewrite_http1_response(raw, &|_, _, body| Ok(body.to_vec())).unwrap_err();

        assert!(
            err.to_string()
                .contains("content-encoded OAuth capture response"),
            "unexpected error: {err}"
        );
    }
}
