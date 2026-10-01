//! spec §6.4: the INI scanner of C `mq_config_load` — `[Section]` headers,
//! `Key = Value` lines, `#`/`;` comments, whitespace trimmed. Names are
//! returned as written (the caller compares them case-insensitively).

/// One meaningful line, with its 1-based number.
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
    Section(&'a str),
    /// The value is non-empty: C treats an empty value as not set and skips it.
    Kv(&'a str, &'a str),
    /// A warning text (malformed header or a line without `=`).
    Malformed(&'static str),
}

pub fn lines(text: &str) -> impl Iterator<Item = (usize, Line<'_>)> {
    text.lines().enumerate().filter_map(|(i, l)| {
        let t = l.trim();
        let line = if t.is_empty() || t.starts_with(['#', ';']) {
            return None;
        } else if let Some(h) = t.strip_prefix('[') {
            // C: everything after the first ']' is ignored.
            match h.split_once(']') {
                Some((name, _)) => Line::Section(name),
                None => Line::Malformed("malformed section header"),
            }
        } else {
            match t.split_once('=') {
                Some((_, v)) if v.trim().is_empty() => return None,
                Some((k, v)) => Line::Kv(k.trim(), v.trim()),
                None => Line::Malformed("malformed line (no '=')"),
            }
        };
        Some((i + 1, line))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_like_c() {
        let got: Vec<_> =
            lines("# c\n ; c\n\n[ Sec ]x\n k = v = w \nEmpty =\nnoeq\n[bad\n").collect();
        assert_eq!(
            got,
            [
                (4, Line::Section(" Sec ")),
                (5, Line::Kv("k", "v = w")),
                (7, Line::Malformed("malformed line (no '=')")),
                (8, Line::Malformed("malformed section header")),
            ]
        );
    }
}
