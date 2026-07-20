//! A resource-bounded JSON object boundary for attacker-controlled protocol documents.
//!
//! `serde_json::Value` intentionally keeps only the last value for a repeated object member.  That
//! behavior is unsafe for protocol metadata because different implementations can act on different
//! values.  This module performs a complete, bounded lexical pass before constructing a `Value` and
//! rejects duplicate member names after JSON escape decoding at every object depth.

use serde_json::{Map, Value};

pub const ABSOLUTE_MAX_JSON_BYTES: usize = 256 * 1024;
pub const ABSOLUTE_MAX_JSON_DEPTH: usize = 16;
pub const ABSOLUTE_MAX_CONTAINER_ENTRIES: usize = 128;
pub const ABSOLUTE_MAX_STRING_BYTES: usize = 224 * 1024;

/// Conservative hard limits shared by Credential Offers and discovery metadata.
pub const DEFAULT_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: ABSOLUTE_MAX_JSON_BYTES,
    max_depth: ABSOLUTE_MAX_JSON_DEPTH,
    max_container_entries: ABSOLUTE_MAX_CONTAINER_ENTRIES,
    max_string_bytes: 8 * 1024,
};

/// Independent limits enforced before a JSON DOM is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonLimits {
    pub max_bytes: usize,
    /// Maximum number of nested arrays/objects, counting the root object as depth one.
    pub max_depth: usize,
    /// Maximum number of members in each object and elements in each array.
    pub max_container_entries: usize,
    /// Maximum decoded UTF-8 length of every string, including object member names.
    pub max_string_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonBoundaryError {
    LimitsExceedHardMaximum,
    InputTooLarge,
    DepthExceeded,
    ContainerEntriesExceeded,
    StringTooLong,
    DuplicateMember,
    InvalidJson,
    NonObjectRoot,
}

/// Parse one JSON object after enforcing all resource and duplicate-member limits.
pub fn parse_object(
    input: &[u8],
    limits: JsonLimits,
) -> Result<Map<String, Value>, JsonBoundaryError> {
    if limits.max_bytes > ABSOLUTE_MAX_JSON_BYTES
        || limits.max_depth > ABSOLUTE_MAX_JSON_DEPTH
        || limits.max_container_entries > ABSOLUTE_MAX_CONTAINER_ENTRIES
        || limits.max_string_bytes > ABSOLUTE_MAX_STRING_BYTES
    {
        return Err(JsonBoundaryError::LimitsExceedHardMaximum);
    }
    if input.len() > limits.max_bytes {
        return Err(JsonBoundaryError::InputTooLarge);
    }
    if core::str::from_utf8(input).is_err() {
        return Err(JsonBoundaryError::InvalidJson);
    }

    let mut scanner = Scanner {
        input,
        position: 0,
        limits,
    };
    scanner.skip_whitespace();
    let root = scanner.parse_value(0)?;
    scanner.skip_whitespace();
    if scanner.position != input.len() {
        return Err(JsonBoundaryError::InvalidJson);
    }
    if root != ValueKind::Object {
        return Err(JsonBoundaryError::NonObjectRoot);
    }

    match serde_json::from_slice(input).map_err(|_| JsonBoundaryError::InvalidJson)? {
        Value::Object(object) => Ok(object),
        _ => Err(JsonBoundaryError::NonObjectRoot),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueKind {
    Object,
    Other,
}

struct Scanner<'a> {
    input: &'a [u8],
    position: usize,
    limits: JsonLimits,
}

impl Scanner<'_> {
    fn parse_value(&mut self, parent_depth: usize) -> Result<ValueKind, JsonBoundaryError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => {
                self.parse_object(parent_depth + 1)?;
                Ok(ValueKind::Object)
            }
            Some(b'[') => {
                self.parse_array(parent_depth + 1)?;
                Ok(ValueKind::Other)
            }
            Some(b'"') => {
                self.parse_string()?;
                Ok(ValueKind::Other)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.parse_number()?;
                Ok(ValueKind::Other)
            }
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(ValueKind::Other)
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(ValueKind::Other)
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(ValueKind::Other)
            }
            _ => Err(JsonBoundaryError::InvalidJson),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), JsonBoundaryError> {
        self.check_depth(depth)?;
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.consume_if(b'}') {
            return Ok(());
        }

        let mut names = Vec::new();
        loop {
            let name = self.parse_string()?;
            if names.iter().any(|seen| seen == &name) {
                return Err(JsonBoundaryError::DuplicateMember);
            }
            names.push(name);
            if names.len() > self.limits.max_container_entries {
                return Err(JsonBoundaryError::ContainerEntriesExceeded);
            }

            self.skip_whitespace();
            self.expect(b':')?;
            self.parse_value(depth)?;
            self.skip_whitespace();
            if self.consume_if(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), JsonBoundaryError> {
        self.check_depth(depth)?;
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.consume_if(b']') {
            return Ok(());
        }

        let mut entries = 0usize;
        loop {
            entries = entries
                .checked_add(1)
                .ok_or(JsonBoundaryError::ContainerEntriesExceeded)?;
            if entries > self.limits.max_container_entries {
                return Err(JsonBoundaryError::ContainerEntriesExceeded);
            }
            self.parse_value(depth)?;
            self.skip_whitespace();
            if self.consume_if(b']') {
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonBoundaryError> {
        self.expect(b'"')?;
        let mut decoded = String::new();
        loop {
            let byte = self.next().ok_or(JsonBoundaryError::InvalidJson)?;
            match byte {
                b'"' => return Ok(decoded),
                b'\\' => {
                    let escaped = self.next().ok_or(JsonBoundaryError::InvalidJson)?;
                    match escaped {
                        b'"' => decoded.push('"'),
                        b'\\' => decoded.push('\\'),
                        b'/' => decoded.push('/'),
                        b'b' => decoded.push('\u{0008}'),
                        b'f' => decoded.push('\u{000c}'),
                        b'n' => decoded.push('\n'),
                        b'r' => decoded.push('\r'),
                        b't' => decoded.push('\t'),
                        b'u' => self.parse_unicode_escape(&mut decoded)?,
                        _ => return Err(JsonBoundaryError::InvalidJson),
                    }
                }
                0x00..=0x1f => return Err(JsonBoundaryError::InvalidJson),
                0x20..=0x7f => decoded.push(char::from(byte)),
                _ => {
                    let width = utf8_width(byte).ok_or(JsonBoundaryError::InvalidJson)?;
                    let start = self.position - 1;
                    let end = start
                        .checked_add(width)
                        .filter(|end| *end <= self.input.len())
                        .ok_or(JsonBoundaryError::InvalidJson)?;
                    let scalar = core::str::from_utf8(&self.input[start..end])
                        .map_err(|_| JsonBoundaryError::InvalidJson)?;
                    decoded.push_str(scalar);
                    self.position = end;
                }
            }
            if decoded.len() > self.limits.max_string_bytes {
                return Err(JsonBoundaryError::StringTooLong);
            }
        }
    }

    fn parse_unicode_escape(&mut self, decoded: &mut String) -> Result<(), JsonBoundaryError> {
        let first = self.parse_hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            self.expect(b'\\')?;
            self.expect(b'u')?;
            let second = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(JsonBoundaryError::InvalidJson);
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(JsonBoundaryError::InvalidJson);
        } else {
            u32::from(first)
        };
        decoded.push(char::from_u32(scalar).ok_or(JsonBoundaryError::InvalidJson)?);
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonBoundaryError> {
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = self.next().ok_or(JsonBoundaryError::InvalidJson)?;
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(u16::from(hex_value(digit)?)))
                .ok_or(JsonBoundaryError::InvalidJson)?;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<(), JsonBoundaryError> {
        self.consume_if(b'-');
        match self.next() {
            Some(b'0') => {
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonBoundaryError::InvalidJson);
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(JsonBoundaryError::InvalidJson),
        }

        if self.consume_if(b'.') {
            if !matches!(self.next(), Some(b'0'..=b'9')) {
                return Err(JsonBoundaryError::InvalidJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.next(), Some(b'0'..=b'9')) {
                return Err(JsonBoundaryError::InvalidJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        Ok(())
    }

    fn consume_literal(&mut self, expected: &[u8]) -> Result<(), JsonBoundaryError> {
        let end = self
            .position
            .checked_add(expected.len())
            .filter(|end| *end <= self.input.len())
            .ok_or(JsonBoundaryError::InvalidJson)?;
        if &self.input[self.position..end] != expected {
            return Err(JsonBoundaryError::InvalidJson);
        }
        self.position = end;
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), JsonBoundaryError> {
        if depth > self.limits.max_depth {
            Err(JsonBoundaryError::DepthExceeded)
        } else {
            Ok(())
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsonBoundaryError> {
        if self.consume_if(expected) {
            Ok(())
        } else {
            Err(JsonBoundaryError::InvalidJson)
        }
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
