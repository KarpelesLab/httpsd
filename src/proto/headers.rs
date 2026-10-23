//! A case-insensitive, order-preserving header collection.

/// An ordered list of HTTP header fields with case-insensitive name lookup.
///
/// Field names are compared ASCII-case-insensitively (per RFC 9110 §5.1) but
/// the original casing is preserved for output. Multiple fields with the same
/// name are allowed and kept in order.
///
/// Field values are bytes on the wire, and RFC 9110 allows non-ASCII
/// `obs-text` (0x80–0xFF) in them — for example a Latin-1 filename in
/// `Content-Disposition`. The `&str` accessors ([`get`](Self::get),
/// [`iter`](Self::iter), …) show such a value decoded lossily (invalid UTF-8
/// becomes U+FFFD), while the `_bytes` accessors ([`get_bytes`](Self::get_bytes),
/// [`iter_bytes`](Self::iter_bytes), …) return the exact bytes. Values set with
/// [`append_bytes`](Self::append_bytes) / [`set_bytes`](Self::set_bytes) are
/// sent byte for byte.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    fields: Vec<Field>,
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    /// The value as text: exact when the bytes are UTF-8, lossy otherwise.
    value: String,
    /// The exact bytes, kept only when they are not valid UTF-8.
    raw: Option<Box<[u8]>>,
}

impl Field {
    fn text(name: String, value: String) -> Field {
        Field {
            name,
            value,
            raw: None,
        }
    }

    fn bytes(name: String, value: Vec<u8>) -> Field {
        match String::from_utf8(value) {
            Ok(value) => Field::text(name, value),
            Err(e) => {
                let raw = e.into_bytes();
                Field {
                    name,
                    value: String::from_utf8_lossy(&raw).into_owned(),
                    raw: Some(raw.into_boxed_slice()),
                }
            }
        }
    }

    fn value_bytes(&self) -> &[u8] {
        self.raw.as_deref().unwrap_or(self.value.as_bytes())
    }

    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

impl Headers {
    /// An empty header set.
    pub fn new() -> Headers {
        Headers { fields: Vec::new() }
    }

    /// Number of header fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether there are no header fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Append a header field, keeping any existing field of the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push(Field::text(name.into(), value.into()));
    }

    /// Append a header field whose value is raw bytes (which need not be
    /// UTF-8), keeping any existing field of the same name.
    pub fn append_bytes(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.fields.push(Field::bytes(name.into(), value.into()));
    }

    /// Set a header field, removing any existing fields of the same name first.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove(&name);
        self.fields.push(Field::text(name, value.into()));
    }

    /// Set a header field to raw bytes (which need not be UTF-8), removing any
    /// existing fields of the same name first.
    pub fn set_bytes(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        let name = name.into();
        self.remove(&name);
        self.fields.push(Field::bytes(name, value.into()));
    }

    /// Set a header only if no field of that name is already present.
    pub fn set_if_absent(&mut self, name: &str, value: impl Into<String>) {
        if !self.contains(name) {
            self.fields.push(Field::text(name.to_owned(), value.into()));
        }
    }

    /// Remove every field with the given (case-insensitive) name.
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|f| !f.is(name));
    }

    /// The first value for `name`, if any (lossily decoded if not UTF-8).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.is(name))
            .map(|f| f.value.as_str())
    }

    /// The exact bytes of the first value for `name`, if any.
    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|f| f.is(name))
            .map(Field::value_bytes)
    }

    /// Iterate over every value for `name` (case-insensitive).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |f| f.is(name))
            .map(|f| f.value.as_str())
    }

    /// Iterate over the exact bytes of every value for `name`.
    pub fn get_all_bytes<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |f| f.is(name))
            .map(Field::value_bytes)
    }

    /// Whether a field with the given name is present.
    pub fn contains(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.is(name))
    }

    /// Iterate over all `(name, value)` pairs in insertion order (values
    /// lossily decoded if not UTF-8).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
    }

    /// Iterate over all `(name, value bytes)` pairs in insertion order.
    pub fn iter_bytes(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.fields
            .iter()
            .map(|f| (f.name.as_str(), f.value_bytes()))
    }

    /// Whether a comma-separated list header contains `token` as one of its
    /// elements, compared case-insensitively. Handy for `Connection`,
    /// `Accept-Encoding`, `Transfer-Encoding`, etc.
    pub fn contains_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_values_round_trip_both_ways() {
        let mut h = Headers::new();
        h.append("X-A", "héllo");
        assert_eq!(h.get("x-a"), Some("héllo"));
        assert_eq!(h.get_bytes("x-a"), Some("héllo".as_bytes()));
    }

    #[test]
    fn non_utf8_value_keeps_exact_bytes() {
        let mut h = Headers::new();
        // "café.txt" in Latin-1.
        let latin1 = b"attachment; filename=\"caf\xe9.txt\"".to_vec();
        h.append_bytes("Content-Disposition", latin1.clone());
        assert_eq!(h.get_bytes("content-disposition"), Some(&latin1[..]));
        assert_eq!(
            h.get("content-disposition"),
            Some("attachment; filename=\"caf\u{fffd}.txt\"")
        );
        let (_, v) = h.iter_bytes().next().unwrap();
        assert_eq!(v, &latin1[..]);
    }

    #[test]
    fn set_bytes_replaces() {
        let mut h = Headers::new();
        h.append("X", "1");
        h.append("x", "2");
        h.set_bytes("X", b"\xff".to_vec());
        assert_eq!(h.len(), 1);
        assert_eq!(h.get_all_bytes("x").collect::<Vec<_>>(), vec![&b"\xff"[..]]);
    }
}
