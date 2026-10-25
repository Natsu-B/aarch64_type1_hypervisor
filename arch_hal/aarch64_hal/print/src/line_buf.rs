//! Fixed-capacity stack buffer for formatting a single log line.

use core::fmt;

/// Stack buffer that collects formatted output and silently truncates past `N` bytes.
///
/// Formatting into this buffer first lets callers emit a whole line with one UART write
/// instead of interleaving fragments with other writers.
pub struct LineBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> LineBuf<N> {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Returns the buffered text, or `None` if truncation split a multi-byte character.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.buf[..self.len]).ok()
    }
}

impl<const N: usize> Default for LineBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for LineBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let avail = self.buf.len().saturating_sub(self.len);
        if avail == 0 {
            return Ok(());
        }
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(avail);
        self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    #[test]
    fn formats_within_capacity() {
        let mut line = LineBuf::<16>::new();
        write!(line, "irq={} ok", 42).unwrap();
        assert_eq!(line.as_str(), Some("irq=42 ok"));
    }

    #[test]
    fn truncates_past_capacity() {
        let mut line = LineBuf::<4>::new();
        write!(line, "abcdef").unwrap();
        assert_eq!(line.as_str(), Some("abcd"));
    }

    #[test]
    fn split_multibyte_char_is_rejected() {
        let mut line = LineBuf::<2>::new();
        write!(line, "aé").unwrap();
        assert_eq!(line.as_str(), None);
    }
}
