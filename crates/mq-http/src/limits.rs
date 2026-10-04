//! Shared nginx-like header limits for both gateway ends (SP4 spec §5).

/// One header field: name + value bytes.
pub const FIELD_MAX: usize = 8192;
/// Whole header section: Σ (name + value + 32), pseudo-headers included.
pub const SECTION_MAX: usize = 32768;
pub const COUNT_MAX: usize = 256;
/// `:path` is a field too, so its value is bounded by `FIELD_MAX - ":path".len()`
/// (SP4 plan refinement R5; the 8192 in spec §5 was a rounded figure).
pub const TARGET_PATH_MAX: usize = FIELD_MAX - 5;
/// Longest method, case preserved.
pub const METHOD_MAX: usize = 32;

/// A header-section limit was exceeded.
#[derive(Debug, PartialEq, Eq)]
pub struct Overflow;

/// Running count/size of a header section.
#[derive(Debug, Default, Clone, Copy)]
pub struct SectionBudget {
    count: usize,
    size: usize,
}

impl SectionBudget {
    pub fn add(&mut self, name: &[u8], value: &[u8]) -> Result<(), Overflow> {
        let field = name.len() + value.len();
        if field > FIELD_MAX || self.count == COUNT_MAX || self.size + field + 32 > SECTION_MAX {
            return Err(Overflow);
        }
        self.count += 1;
        self.size += field + 32;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_field_8192_ok_8193_overflow() {
        let mut b = SectionBudget::default();
        assert_eq!(b.add(b"n", &vec![b'a'; 8191]), Ok(()));
        let mut b = SectionBudget::default();
        assert_eq!(b.add(b"n", &vec![b'a'; 8192]), Err(Overflow));
        assert_eq!((b.count(), b.size()), (0, 0));
    }

    #[test]
    fn budget_section_exact_32768_ok_plus_one_overflow() {
        let mut b = SectionBudget::default();
        let name = [b'n'; 8];
        for _ in 0..4 {
            // 8 + 8120 = 8128 field bytes, +32 = 8160 each.
            assert_eq!(b.add(&name, &vec![b'v'; 8120]), Ok(()));
        }
        assert_eq!(b.size(), 4 * 8160);
        // 32768 - 32640 = 128 left: a field of 96 bytes (+32) lands exactly.
        let mut exact = b;
        assert_eq!(exact.add(&name, &[b'v'; 88]), Ok(()));
        assert_eq!(exact.size(), SECTION_MAX);
        assert_eq!(exact.count(), 5);
        // One more byte overflows.
        let mut over = b;
        assert_eq!(over.add(&name, &[b'v'; 89]), Err(Overflow));
        // The exact section is full: even the smallest field overflows.
        assert_eq!(exact.add(b"a", b""), Err(Overflow));
    }

    #[test]
    fn budget_count_256_ok_257_overflow() {
        let mut b = SectionBudget::default();
        for _ in 0..COUNT_MAX {
            assert_eq!(b.add(b"a", b"b"), Ok(()));
        }
        assert_eq!(b.count(), 256);
        assert!(b.size() < SECTION_MAX);
        assert_eq!(b.add(b"a", b"b"), Err(Overflow));
    }
}
