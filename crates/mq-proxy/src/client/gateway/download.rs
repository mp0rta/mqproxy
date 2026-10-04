//! SP3 spec §5.4: the fetch download's response head — collected from the H3
//! header section under the shared limits (SP4 spec §5), rendered as the local
//! HTTP/1.1 head (`adp_resp_head`).

use mq_http::h1;
use mq_http::limits::SECTION_MAX;

pub(super) use crate::client::exchange::resp::{HeadCollector, Malformed, RespHead};

/// SP4 spec §5: the render buffer, `SECTION_MAX` plus room for the status line
/// and the `Transfer-Encoding` / `Connection` lines.
const RESP_RENDER_MAX: usize = SECTION_MAX + 1024;

/// Status line (empty reason), the headers as received (`content-length`
/// rewritten to `0` for a `HEAD` fetch, §12), `Transfer-Encoding: chunked`
/// without a `content-length`, `Connection: close`, blank line; over `RESP_RENDER_MAX` bytes
/// is malformed.
pub fn render_head(h: &RespHead, fetch_method_is_head: bool) -> Result<Vec<u8>, Malformed> {
    let mut o = Vec::with_capacity(512);
    h1::write_status(&mut o, h.status, "");
    for (n, v) in &h.headers {
        let v: &[u8] = if fetch_method_is_head && n.eq_ignore_ascii_case(b"content-length") {
            b"0"
        } else {
            v
        };
        h1::write_header(&mut o, n, v).map_err(|_| Malformed)?;
    }
    if !h.has_cl {
        h1::write_header(&mut o, b"Transfer-Encoding", b"chunked").map_err(|_| Malformed)?;
    }
    h1::write_header(&mut o, b"Connection", b"close").map_err(|_| Malformed)?;
    o.extend_from_slice(b"\r\n");
    if o.len() > RESP_RENDER_MAX {
        return Err(Malformed);
    }
    Ok(o)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn collect(hs: &[(&str, &str)], fin: bool) -> Result<RespHead, Malformed> {
        let mut c = HeadCollector::default();
        for (n, v) in hs {
            c.push(n.as_bytes(), v.as_bytes());
        }
        c.finish(fin)
    }

    fn render(hs: &[(&str, &str)], is_head: bool) -> Result<Vec<u8>, Malformed> {
        render_head(&collect(hs, false)?, is_head)
    }

    #[test]
    fn head_render_golden_cl() {
        let got = render(
            &[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ],
            false,
        );
        assert_eq!(
            got.unwrap(),
            b"HTTP/1.1 200 \r\ncontent-type: text/plain\r\ncontent-length: 5\r\nConnection: close\r\n\r\n"
        );
        let h = collect(&[(":status", "200"), ("content-length", "5")], true).unwrap();
        assert_eq!((h.cl, h.has_cl, h.fin), (Some(5), true, true));
    }

    #[test]
    fn head_render_golden_chunked() {
        let got = render(&[("content-type", "text/plain"), (":status", "404")], false);
        assert_eq!(
            got.unwrap(),
            b"HTTP/1.1 404 \r\ncontent-type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    /// `:status: 200` costs 7 + 3 + 32 = 42; seven 4032-byte fields and one of 4502
    /// fill SECTION_MAX exactly.
    fn full_section<'a>(v: &'a str, last: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut hs = vec![(":status", "200")];
        hs.extend([("n", v); 7]);
        hs.push(("n", last));
        hs
    }

    #[test]
    fn render_head_near_section_max_fits() {
        // A section filling SECTION_MAX renders (about 32.5 KiB) within the cap.
        let (v, last) = ("v".repeat(3999), "v".repeat(4469));
        let got = render(&full_section(&v, &last), false).unwrap();
        assert!(
            got.len() > 32_000 && got.len() <= RESP_RENDER_MAX,
            "{}",
            got.len()
        );
    }

    #[test]
    fn head_render_over_8192_ok() {
        // SP3's 8 KiB render cap is gone: the old at-the-cap fixture plus one byte.
        let fits = "v".repeat(8192 - 55 - 5 - 4 * 2005 + 1);
        let big = "v".repeat(2000);
        let mut hs = vec![(":status", "200"), ("content-length", "0")];
        hs.extend([("x", big.as_str()); 4]);
        hs.push(("x", &fits));
        assert_eq!(render(&hs, false).unwrap().len(), 8193);
    }

    #[test]
    fn head_render_over_render_max_malformed() {
        // The collector cannot produce this (a rendered field is 4 bytes over its
        // content, the budget's is 32), so build the head directly.
        let mk = |n: usize| RespHead {
            status: 200,
            headers: vec![(b"x".to_vec(), vec![b'v'; n])],
            cl: None,
            has_cl: true,
            fin: false,
        };
        // "HTTP/1.1 200 \r\n" (15) + "x: <v>\r\n" (5 + n) + "Connection: close\r\n" (19) + "\r\n" (2).
        let fits = RESP_RENDER_MAX - 15 - 5 - 19 - 2;
        let at_cap = render_head(&mk(fits), false).unwrap();
        assert_eq!(at_cap.len(), RESP_RENDER_MAX);
        assert_eq!(render_head(&mk(fits + 1), false), Err(Malformed));
    }

    #[test]
    fn head_fetch_method_head_rewrites_cl_to_0() {
        let hs = [(":status", "200"), ("content-length", "1234")];
        assert_eq!(
            render(&hs, true).unwrap(),
            b"HTTP/1.1 200 \r\ncontent-length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            render(&hs, false).unwrap(),
            b"HTTP/1.1 200 \r\ncontent-length: 1234\r\nConnection: close\r\n\r\n"
        );
    }
}
