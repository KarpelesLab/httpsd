//! A case-insensitive, order-preserving header collection.

/// An ordered list of HTTP header fields with case-insensitive name lookup.
///
/// Field names are compared ASCII-case-insensitively (per RFC 9110 §5.1) but
/// the original casing is preserved for output. Multiple fields with the same
/// name are allowed and kept in order.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    fields: Vec<(String, String)>,
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
        self.fields.push((name.into(), value.into()));
    }

    /// Set a header field, removing any existing fields of the same name first.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove(&name);
        self.fields.push((name, value.into()));
    }

    /// Set a header only if no field of that name is already present.
    pub fn set_if_absent(&mut self, name: &str, value: impl Into<String>) {
        if self.get(name).is_none() {
            self.fields.push((name.to_owned(), value.into()));
        }
    }

    /// Remove every field with the given (case-insensitive) name.
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// The first value for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Iterate over every value for `name` (case-insensitive).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a field with the given name is present.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Iterate over all `(name, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether a comma-separated list header contains `token` as one of its
    /// elements, compared case-insensitively. Handy for `Connection`,
    /// `Accept-Encoding`, `Transfer-Encoding`, etc.
    pub fn contains_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
}
