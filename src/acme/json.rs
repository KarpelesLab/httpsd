//! A small JSON reader/writer scoped to ACME's needs (RFC 8259).
//!
//! ACME responses are small and well-structured; a focused parser keeps the
//! `acme` feature's only external dependency the `rsurl` HTTP client. Outbound
//! request bodies are tiny and assembled with [`obj`]/[`escape`] rather than a
//! full serializer.

use crate::error::{Error, Result};

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)] // variant names are the JSON type names
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Field lookup for objects.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// The string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    /// The array elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Convenience: the string at object field `key`.
    pub fn str_at(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }
}

/// Parse a JSON document.
pub fn parse(input: &str) -> Result<Value> {
    let bytes = input.as_bytes();
    let mut p = Parser { b: bytes, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != bytes.len() {
        return Err(err("trailing data after JSON value"));
    }
    Ok(v)
}

fn err(msg: &str) -> Error {
    Error::Config(format!("json: {msg}"))
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<Value> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(err("unexpected token")),
        }
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(err("invalid literal"))
        }
    }
    fn object(&mut self) -> Result<Value> {
        self.i += 1; // {
        let mut fields = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(err("expected object key"));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(err("expected ':'"));
            }
            self.i += 1;
            let val = self.value()?;
            fields.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(err("expected ',' or '}'")),
            }
        }
        Ok(Value::Object(fields))
    }
    fn array(&mut self) -> Result<Value> {
        self.i += 1; // [
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(err("expected ',' or ']'")),
            }
        }
        Ok(Value::Array(items))
    }
    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or_else(|| err("unterminated string"))?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or_else(|| err("bad escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'u' => {
                            let hex = self
                                .b
                                .get(self.i..self.i + 4)
                                .ok_or_else(|| err("short \\u"))?;
                            let cp = u32::from_str_radix(
                                std::str::from_utf8(hex).map_err(|_| err("bad \\u"))?,
                                16,
                            )
                            .map_err(|_| err("bad \\u"))?;
                            self.i += 4;
                            let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                            let mut tmp = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        _ => return Err(err("unknown escape")),
                    }
                }
                // Any other byte (including UTF-8 continuation bytes) is copied
                // verbatim; the whole buffer is validated as UTF-8 at the end.
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| err("invalid UTF-8 string"))
    }
    fn number(&mut self) -> Result<Value> {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c == b'-' || c == b'+' || c == b'.' || c == b'e' || c == b'E' || c.is_ascii_digit())
        {
            self.i += 1;
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| err("bad number"))?;
        text.parse::<f64>()
            .map(Value::Num)
            .map_err(|_| err("bad number"))
    }
}

/// Escape a string for inclusion in a JSON document (no surrounding quotes).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Build a JSON object from `(key, raw_json_value)` pairs. Values are inserted
/// verbatim, so quote strings with `"\"{}\""` or `escape`.
pub fn obj(fields: &[(&str, String)]) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape(k));
        out.push_str("\":");
        out.push_str(v);
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested() {
        let v = parse(r#"{"a":1,"b":[true,null,"x"],"c":{"d":"e"}}"#).unwrap();
        assert_eq!(v.get("c").unwrap().str_at("d"), Some("e"));
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("b").unwrap().as_array().unwrap()[2].as_str(), Some("x"));
        assert_eq!(v.get("a"), Some(&Value::Num(1.0)));
    }

    #[test]
    fn handles_escapes_and_unicode() {
        let v = parse(r#"{"k":"line\nbreak \" é café"}"#).unwrap();
        assert_eq!(v.str_at("k"), Some("line\nbreak \" é café"));
    }

    #[test]
    fn builds_objects() {
        let body = obj(&[
            ("termsOfServiceAgreed", "true".into()),
            ("contact", r#"["mailto:a@b.test"]"#.into()),
        ]);
        let v = parse(&body).unwrap();
        assert_eq!(v.get("termsOfServiceAgreed"), Some(&Value::Bool(true)));
        assert_eq!(
            v.get("contact").unwrap().as_array().unwrap()[0].as_str(),
            Some("mailto:a@b.test")
        );
    }

    #[test]
    fn escape_basic() {
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}
