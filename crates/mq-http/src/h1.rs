//! HTTP/1.1 request head parser (spec §2.1).

pub const HEAD_MAX: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
/// Longest method (bytes) of the fetch listener's own request line only;
/// the shared method bound is `limits::METHOD_MAX`.
pub const METHOD_MAX: usize = 15;
/// Longest request-target of the fetch listener's own request line only;
/// the shared bound is `limits::TARGET_PATH_MAX`.
pub const PATH_MAX: usize = 1023;

/// One header line; `value` is OWS-trimmed.
#[derive(Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Head<'a> {
    pub method: &'a [u8],
    pub target: &'a [u8],
    pub headers: Vec<Header<'a>>,
    pub content_length: Option<u64>,
    pub has_chunked_te: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Progress<'a> {
    Need,
    TooLarge,
    Bad,
    Done { consumed: usize, head: Head<'a> },
}

pub(crate) fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn is_ows(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [f, r @ ..] = v {
        if !is_ows(*f) {
            break;
        }
        v = r;
    }
    while let [r @ .., l] = v {
        if !is_ows(*l) {
            break;
        }
        v = r;
    }
    v
}

/// Strict decimal in `0..=i64::MAX` (leading zeros accepted).
pub fn parse_content_length(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in v {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
        if n > i64::MAX as u64 {
            return None;
        }
    }
    Some(n)
}

/// Does a comma-separated Transfer-Encoding value list `chunked`?
fn te_lists_chunked(v: &[u8]) -> bool {
    v.split(|&c| c == b',')
        .any(|t| trim_ows(t).eq_ignore_ascii_case(b"chunked"))
}

/// Parse a request head from the start of `buf` (spec §2.1). A head whose
/// terminator lies beyond `HEAD_MAX` is `TooLarge`.
pub fn parse_head(buf: &[u8]) -> Progress<'_> {
    let Some(p) = find(buf, b"\r\n\r\n") else {
        return if buf.len() >= HEAD_MAX {
            Progress::TooLarge
        } else {
            Progress::Need
        };
    };
    let hend = p + 4;
    if hend > HEAD_MAX {
        return Progress::TooLarge;
    }
    match parse_complete(&buf[..hend]) {
        Some(head) => Progress::Done {
            consumed: hend,
            head,
        },
        None => Progress::Bad,
    }
}

/// `head` ends with the first `\r\n\r\n`; `None` = malformed.
fn parse_complete(head: &[u8]) -> Option<Head<'_>> {
    let line_end = find(head, b"\r\n")?;
    let line = &head[..line_end];

    // METHOD SP TARGET SP HTTP/...
    let m_end = line.iter().position(|&c| c == b' ')?;
    let method = &line[..m_end];
    if method.is_empty() || method.len() > METHOD_MAX || !method.iter().all(|&c| is_tchar(c)) {
        return None;
    }
    let rest = &line[m_end + 1..];
    let t_end = rest.iter().position(|&c| c == b' ')?;
    let target = &rest[..t_end];
    // < 1024 bytes, origin-form, no control bytes / DEL.
    if target.first() != Some(&b'/') || target.len() > PATH_MAX {
        return None;
    }
    if target.iter().any(|&c| c < 0x20 || c == 0x7f) {
        return None;
    }
    // any non-empty `HTTP/`-prefixed version (the gateway never branches on it)
    if !rest[t_end + 1..].starts_with(b"HTTP/") {
        return None;
    }

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut has_chunked_te = false;
    let mut pos = line_end + 2;
    let headers_end = head.len() - 2; // the blank line's CR
    while pos < headers_end {
        if is_ows(head[pos]) {
            return None; // obs-fold
        }
        let le = pos + find(&head[pos..], b"\r\n")?;
        let hline = &head[pos..le];
        if headers.len() >= MAX_HEADERS {
            return None;
        }
        let colon = hline.iter().position(|&c| c == b':')?;
        let name = &hline[..colon];
        if name.is_empty() || !name.iter().all(|&c| is_tchar(c)) {
            return None;
        }
        let raw = &hline[colon + 1..];
        if raw.iter().any(|&c| c == 0 || c == b'\r') {
            return None;
        }
        let value = trim_ows(raw);
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return None;
            }
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") && te_lists_chunked(value) {
            has_chunked_te = true;
        }
        headers.push(Header { name, value });
        pos = le + 2;
    }
    Some(Head {
        method,
        target,
        headers,
        content_length,
        has_chunked_te,
    })
}

// ---- serializer (spec §2.2) ----

/// `HTTP/1.1 <code> <reason>\r\n`; the fetch client passes an empty reason.
pub fn write_status(out: &mut Vec<u8>, code: u16, reason: &str) {
    out.extend_from_slice(format!("HTTP/1.1 {code} {reason}\r\n").as_bytes());
}

/// A header name or value contained CR, LF or NUL.
#[derive(Debug, PartialEq, Eq)]
pub struct BadHeaderBytes;

/// `name: value\r\n`; refuses CR/LF/NUL (response-splitting guard), writing nothing.
pub fn write_header(out: &mut Vec<u8>, name: &[u8], value: &[u8]) -> Result<(), BadHeaderBytes> {
    if name
        .iter()
        .chain(value)
        .any(|&c| matches!(c, b'\r' | b'\n' | 0))
    {
        return Err(BadHeaderBytes);
    }
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// `<lowercase hex len>\r\n<data>\r\n`; never called with empty `data`.
pub fn chunk_frame(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(!data.is_empty(), "a zero-length chunk would end the body");
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// The chunked-body terminator `0\r\n\r\n`.
pub fn chunk_end(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

/// Listener/reject reply: status, `Connection: close`, `Content-Length: 0`,
/// optional `X-Mq-Error`, blank line.
pub fn error_reply(code: u16, reason: &str, xmq: Option<&str>) -> Vec<u8> {
    let mut o = Vec::with_capacity(96);
    write_status(&mut o, code, reason);
    // fixed names/values: cannot fail
    let _ = write_header(&mut o, b"Connection", b"close");
    let _ = write_header(&mut o, b"Content-Length", b"0");
    if let Some(x) = xmq {
        // ponytail: a CR/LF/NUL in `x` drops the header; callers pass the §9.1 constants
        let _ = write_header(&mut o, b"X-Mq-Error", x.as_bytes());
    }
    o.extend_from_slice(b"\r\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(buf: &[u8]) -> (usize, Head<'_>) {
        match parse_head(buf) {
            Progress::Done { consumed, head } => (consumed, head),
            other => panic!("expected Done, got {other:?}"),
        }
    }
    fn bad(buf: &[u8]) {
        assert_eq!(
            parse_head(buf),
            Progress::Bad,
            "{:?}",
            String::from_utf8_lossy(buf)
        );
    }
    fn with_headers(n: usize) -> Vec<u8> {
        let mut b = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..n {
            b.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        b.extend_from_slice(b"\r\n");
        b
    }
    fn cl(v: &str) -> Vec<u8> {
        format!("POST / HTTP/1.1\r\nContent-Length: {v}\r\n\r\n").into_bytes()
    }

    #[test]
    fn parses_minimal_post_fetch() {
        let req = b"POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n\r\n";
        let (consumed, h) = done(req);
        assert_eq!(consumed, req.len());
        assert_eq!(h.method, b"POST");
        assert_eq!(h.target, b"/_mqproxy/fetch");
        assert_eq!(h.content_length, None);
        assert!(!h.has_chunked_te);
        assert_eq!(
            h.headers,
            [Header {
                name: b"Host",
                value: b"x"
            }]
        );
    }

    #[test]
    fn normal_post_body_not_consumed() {
        let req = b"POST /_mqproxy/fetch HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\nhello world";
        let (consumed, h) = done(req);
        assert_eq!(consumed, req.len() - 11);
        assert_eq!(h.content_length, Some(11));
        assert_eq!(h.headers.len(), 3);
        assert_eq!(h.headers[1].value, b"application/json");
    }

    #[test]
    fn need_more_without_blank_line() {
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\nHost: x\r\n"), Progress::Need);
        assert_eq!(parse_head(b""), Progress::Need);
    }

    #[test]
    fn split_arrival() {
        let full = b"POST /_mqproxy/fetch HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_head(&full[..full.len() - 1]), Progress::Need);
        let (consumed, h) = done(full);
        assert_eq!(consumed, full.len());
        assert_eq!(h.method, b"POST");
        assert_eq!(h.target, b"/_mqproxy/fetch");
        assert_eq!(h.content_length, Some(0));
    }

    #[test]
    fn too_large_at_16k_without_terminator() {
        let mut b = vec![b'a'; HEAD_MAX];
        b[..5].copy_from_slice(b"GET /");
        assert_eq!(parse_head(&b), Progress::TooLarge);
        assert_eq!(parse_head(&b[..HEAD_MAX - 1]), Progress::Need);
        b.push(b'a');
        assert_eq!(parse_head(&b), Progress::TooLarge);
    }

    #[test]
    fn head_exactly_16k_ok() {
        let mut b = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        b.resize(HEAD_MAX - 4, b'a');
        b.extend_from_slice(b"\r\n\r\n");
        assert_eq!(b.len(), HEAD_MAX);
        let (consumed, h) = done(&b);
        assert_eq!(consumed, HEAD_MAX);
        assert_eq!(h.headers.len(), 1);
        // one byte more with the terminator still present: over the cap
        let mut b = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        b.resize(HEAD_MAX - 3, b'a');
        b.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse_head(&b), Progress::TooLarge);
    }

    #[test]
    fn method_16_bytes_bad() {
        bad(b"ABCDEFGHIJKLMNOP / HTTP/1.1\r\n\r\n");
        let (_, h) = done(b"ABCDEFGHIJKLMNO / HTTP/1.1\r\n\r\n");
        assert_eq!(h.method.len(), 15);
    }

    #[test]
    fn method_non_tchar_bad() {
        bad(b"PO()ST / HTTP/1.1\r\n\r\n");
    }

    fn get_with_target_len(n: usize) -> Vec<u8> {
        let mut b = b"GET /".to_vec();
        b.resize(4 + n, b'a');
        b.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        b
    }

    #[test]
    fn target_1024_bad() {
        bad(&get_with_target_len(1024));
        bad(&{
            let mut b = b"GET /".to_vec();
            b.resize(5 + 1100, b'a');
            b.extend_from_slice(b" HTTP/1.1\r\n\r\n");
            b
        });
    }

    #[test]
    fn target_1023_ok() {
        let b = get_with_target_len(1023);
        let (_, h) = done(&b);
        assert_eq!(h.target.len(), 1023);
    }

    #[test]
    fn target_not_starting_with_slash_bad() {
        bad(b"GET http://x/ HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn path_nul() {
        bad(b"GET /a\0b HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn path_ctrl_1f() {
        bad(b"GET /a\x1fb HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn path_del() {
        bad(b"GET /a\x7fb HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn no_version() {
        bad(b"GET /\r\n\r\n");
    }

    #[test]
    fn version_prefix_only_checked() {
        done(b"GET / HTTP/1.0\r\n\r\n");
        done(b"GET / HTTP/9\r\n\r\n");
        bad(b"GET / HTTQ/1.1\r\n\r\n");
    }

    #[test]
    fn obs_fold_bad() {
        bad(b"GET / HTTP/1.1\r\nX-Fold: a\r\n continued\r\n\r\n");
        bad(b"GET / HTTP/1.1\r\nX-Fold: a\r\n\tcontinued\r\n\r\n");
    }

    #[test]
    fn bare_cr_bad() {
        bad(b"GET / HTTP/1.1\r\nX-Bad: a\rb\r\n\r\n");
    }

    #[test]
    fn nul_in_value_bad() {
        bad(b"GET / HTTP/1.1\r\nX-Bad: a\0b\r\n\r\n");
    }

    #[test]
    fn non_token_name_bad() {
        bad(b"GET / HTTP/1.1\r\nBad Name: v\r\n\r\n");
    }

    #[test]
    fn header_no_colon() {
        bad(b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n");
    }

    #[test]
    fn header_empty_name() {
        bad(b"GET / HTTP/1.1\r\n: value\r\n\r\n");
    }

    #[test]
    fn sixty_four_headers_ok() {
        let b = with_headers(MAX_HEADERS);
        assert_eq!(done(&b).1.headers.len(), 64);
    }

    #[test]
    fn sixty_five_bad() {
        bad(&with_headers(MAX_HEADERS + 1));
    }

    #[test]
    fn content_length_parsed() {
        assert_eq!(done(&cl("0")).1.content_length, Some(0));
        assert_eq!(
            done(&cl("9223372036854775807")).1.content_length,
            Some(i64::MAX as u64)
        );
        assert_eq!(done(&cl(" 5")).1.content_length, Some(5)); // OWS
        assert_eq!(
            done(b"POST / HTTP/1.1\r\ncontent-length:\t7 \r\n\r\n")
                .1
                .content_length,
            Some(7)
        );
        assert_eq!(done(&cl("007")).1.content_length, Some(7));
    }

    #[test]
    fn content_length_overflow_bad() {
        bad(&cl("9223372036854775808"));
        bad(&cl("99999999999999999999"));
    }

    #[test]
    fn content_length_non_digit_bad() {
        bad(&cl("-1"));
        bad(&cl(""));
        bad(&cl("12x"));
    }

    #[test]
    fn duplicate_content_length_identical_bad() {
        bad(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
    }

    #[test]
    fn duplicate_content_length_differing_bad() {
        bad(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n");
    }

    #[test]
    fn chunked_te_flagged_not_rejected() {
        let (_, h) = done(b"POST / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n");
        assert!(h.has_chunked_te);
        assert_eq!(h.content_length, None);
    }

    #[test]
    fn te_chunked_list() {
        assert!(
            done(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
                .1
                .has_chunked_te
        );
        assert!(
            !done(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n")
                .1
                .has_chunked_te
        );
    }

    #[test]
    fn cl_and_te() {
        let (_, h) =
            done(b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(h.content_length, Some(5));
        assert!(h.has_chunked_te);
    }

    #[test]
    fn values_ows_trimmed() {
        let (_, h) = done(b"GET / HTTP/1.1\r\nX-Trim: \t  value here  \t\r\n\r\n");
        assert_eq!(h.headers[0].name, b"X-Trim");
        assert_eq!(h.headers[0].value, b"value here");
    }

    #[test]
    fn dup_headers_preserved() {
        let (_, h) = done(b"GET / HTTP/1.1\r\nX-Mq-Tag: a\r\nX-Mq-Tag: b\r\n\r\n");
        let v: Vec<&[u8]> = h.headers.iter().map(|x| x.value).collect();
        assert_eq!(v, [b"a".as_slice(), b"b".as_slice()]);
    }

    // ---- serializer (spec §2.2) ----

    fn bytes(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut v = Vec::new();
        f(&mut v);
        v
    }

    #[test]
    fn status_line_empty_reason_golden() {
        assert_eq!(bytes(|o| write_status(o, 200, "")), b"HTTP/1.1 200 \r\n");
    }

    #[test]
    fn status_line_with_reason() {
        assert_eq!(
            bytes(|o| write_status(o, 200, "OK")),
            b"HTTP/1.1 200 OK\r\n"
        );
        assert_eq!(
            bytes(|o| write_status(o, 411, "Length Required")),
            b"HTTP/1.1 411 Length Required\r\n"
        );
    }

    #[test]
    fn write_header_golden_and_appends() {
        let mut o = b"pre".to_vec();
        write_header(&mut o, b"Content-Length", b"42").unwrap();
        assert_eq!(o, b"preContent-Length: 42\r\n");
    }

    #[test]
    fn write_header_rejects_cr_lf_nul() {
        let mut o = Vec::new();
        assert_eq!(
            write_header(&mut o, b"X-Test", b"a\r\nEvil: x"),
            Err(BadHeaderBytes)
        );
        assert_eq!(write_header(&mut o, b"X-Te\nst", b"v"), Err(BadHeaderBytes));
        assert_eq!(
            write_header(&mut o, b"X-Test", b"a\0b"),
            Err(BadHeaderBytes)
        );
        assert!(o.is_empty(), "nothing written on error");
        write_header(&mut o, b"X-Test", b"clean value").unwrap();
        assert_eq!(o, b"X-Test: clean value\r\n");
    }

    #[test]
    fn chunk_frame_hex_lowercase() {
        assert_eq!(bytes(|o| chunk_frame(o, b"ab")), b"2\r\nab\r\n");
        assert_eq!(bytes(|o| chunk_frame(o, b"hello")), b"5\r\nhello\r\n");
        let big = [b'z'; 26];
        let f = bytes(|o| chunk_frame(o, &big));
        assert_eq!(&f[..4], b"1a\r\n");
        assert_eq!(f.len(), 4 + 26 + 2);
        let big = [b'z'; 4096];
        let f = bytes(|o| chunk_frame(o, &big));
        assert!(f.starts_with(b"1000\r\nzzz"));
        assert!(f.ends_with(b"zz\r\n"));
        assert_eq!(f.len(), 6 + 4096 + 2);
    }

    #[test]
    fn chunk_end_golden() {
        assert_eq!(bytes(chunk_end), b"0\r\n\r\n");
    }

    #[test]
    fn error_reply_400_golden() {
        assert_eq!(
            error_reply(400, "Bad Request", None),
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn error_reply_with_xmq_golden() {
        assert_eq!(
            error_reply(400, "Bad Request", Some("bad-target")),
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Mq-Error: bad-target\r\n\r\n"
        );
    }
}
