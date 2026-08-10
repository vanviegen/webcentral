//! Scanner for the webcentral configuration language.
//!
//! The language has exactly two contexts, and which one you are in is always known from the
//! enclosing block rather than from the line itself:
//!
//! * *Statements* - `verb positional... name=value...`, optionally followed by a `{ ... }` block.
//!   This is the top level of the file and the body of `match`/`else`.
//! * *Settings* - `key = value`, one per line. This is the body of `settings`, `env` and
//!   the server declarations.
//!
//! A word is a run of bare, `"double quoted"` and `'single quoted'` segments glued together, like
//! a shell word, so `header="Auth: Bearer x"` is one word and `"weird key"` is a key with a space
//! in it. Quoting is only ever needed for whitespace, a leading `#`, a standalone brace, or an `=`
//! that must not be read as a separator - every other character, `$` and `{2}` included, is an
//! ordinary word character. That is what lets regexes and argon2 hashes be written as they are.
//!
//! The two quotes differ in one way: `$` substitution happens inside double quotes and not inside
//! single ones. The scanner records which parts of a word came from single quotes so that whoever
//! substitutes can leave them alone.
//!
//! Errors never abort the parse: they are collected and the scanner skips to the next line, so one
//! run reports every problem in the file rather than only the first.

use std::fmt;

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}:{}: {}", self.line, self.col, self.message)
    }
}

/// A single word, with the offset it started at so later validation (an invalid regex, an unknown
/// server name) can still point at the right place.
#[derive(Debug, Clone)]
pub struct Word {
    pub text: String,
    pub pos: usize,
    /// Index in `text` of the first `=` that was written outside quotes, if any. This is what
    /// tells `name=value` apart from a positional argument that merely contains an `=`: quoting
    /// any part of it (`"a=b"`) leaves this `None`.
    pub eq_at: Option<usize>,
    /// Ranges of `text` that came from `'single quotes'`, and so are exempt from substitution.
    pub literal: Vec<(usize, usize)>,
}

impl Word {
    pub fn new(text: impl Into<String>, pos: usize) -> Self {
        Word { text: text.into(), pos, eq_at: None, literal: Vec::new() }
    }

    /// Whether the character at `index` was written inside single quotes.
    pub fn is_literal_at(&self, index: usize) -> bool {
        self.literal.iter().any(|(start, end)| index >= *start && index < *end)
    }
}

impl Word {
    /// The value half of a `name=value` argument, keeping whichever of its parts were literal.
    pub fn named_value(&self, value: &str) -> Word {
        let offset = self.eq_at.map(|i| i + 1).unwrap_or(0);
        Word {
            text: value.to_string(),
            pos: self.pos,
            eq_at: None,
            literal: self
                .literal
                .iter()
                .filter(|(_, end)| *end > offset)
                .map(|(start, end)| (start.saturating_sub(offset), end - offset))
                .collect(),
        }
    }

    /// Split at the first unquoted `=`, for `name=value` arguments.
    pub fn split_eq(&self) -> Option<(&str, &str)> {
        let index = self.eq_at?;
        Some((&self.text[..index], &self.text[index + 1..]))
    }
}

pub struct Scanner<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    pub errors: Vec<Diagnostic>,
}

impl<'a> Scanner<'a> {
    pub fn new(src: &'a str) -> Self {
        Scanner { src, bytes: src.as_bytes(), pos: 0, errors: Vec::new() }
    }

    fn at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    /// Horizontal whitespace and comments. Newlines are significant, so they are left alone.
    fn skip_blank(&mut self) {
        loop {
            match self.at(0) {
                Some(b' ') | Some(b'\t') | Some(b'\r') => self.pos += 1,
                // A `#` only starts a comment at the start of a word, so colours and URL
                // fragments don't need quoting.
                Some(b'#') => {
                    while !matches!(self.at(0), None | Some(b'\n')) {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    pub fn at_eof(&mut self) -> bool {
        self.skip_blank();
        self.pos >= self.bytes.len()
    }

    /// Consume statement separators. Newlines end a statement; so does a `;`, for the occasional
    /// one-liner.
    pub fn skip_separators(&mut self) -> bool {
        let mut found = false;
        loop {
            self.skip_blank();
            if matches!(self.at(0), Some(b'\n') | Some(b';')) {
                self.pos += 1;
                found = true;
            } else {
                return found;
            }
        }
    }

    pub fn at_statement_end(&mut self) -> bool {
        self.skip_blank();
        matches!(self.at(0), None | Some(b'\n') | Some(b';'))
    }

    /// True when the upcoming word is exactly `{` or `}`. Glued braces (`/x{2}`) are word
    /// characters, so only a brace standing on its own is structure.
    fn at_standalone(&mut self, brace: u8) -> bool {
        self.skip_blank();
        if self.at(0) != Some(brace) {
            return false;
        }
        matches!(
            self.at(1),
            None | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') | Some(b';') | Some(b'#')
        )
    }

    pub fn read_block_open(&mut self) -> bool {
        if self.at_standalone(b'{') {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub fn at_block_close(&mut self) -> bool {
        self.at_standalone(b'}')
    }

    pub fn read_block_close(&mut self) -> bool {
        if self.at_standalone(b'}') {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// A word: bare and `"quoted"` segments up to whitespace, a separator or a standalone brace.
    /// `stop_at_eq` ends it at the first unquoted `=` instead of recording it, which is how the
    /// key of a setting is read.
    fn scan_word(&mut self, stop_at_eq: bool) -> Option<Word> {
        self.skip_blank();
        let start = self.pos;
        if matches!(self.at(0), None | Some(b'\n') | Some(b';')) {
            return None;
        }
        if self.at_standalone(b'{') || self.at_standalone(b'}') {
            return None;
        }

        let mut text = String::new();
        let mut eq_at = None;
        let mut any = false;
        let mut literal = Vec::new();

        loop {
            match self.at(0) {
                None | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') | Some(b';') => break,
                Some(b'"') => {
                    any = true;
                    self.scan_quoted(&mut text);
                }
                Some(b'\'') => {
                    any = true;
                    let start = text.len();
                    self.scan_single_quoted(&mut text);
                    literal.push((start, text.len()));
                }
                Some(b'=') => {
                    if stop_at_eq {
                        break;
                    }
                    if eq_at.is_none() {
                        eq_at = Some(text.len());
                    }
                    text.push('=');
                    self.pos += 1;
                    any = true;
                }
                Some(c) => {
                    // A brace glued to what precedes it is an ordinary character, never
                    // structure: that is what lets `${1}` end a word and `x{2}` be a quantifier.
                    // A brace that *starts* a word was already dealt with above.
                    let len = utf8_len(c);
                    text.push_str(&self.src[self.pos..self.pos + len]);
                    self.pos += len;
                    any = true;
                }
            }
        }

        if !any {
            return None;
        }
        Some(Word { text, pos: start, eq_at, literal })
    }

    /// `'...'` is taken exactly as written: no escapes, and no `$` substitution later.
    fn scan_single_quoted(&mut self, text: &mut String) {
        let start = self.pos;
        self.pos += 1;
        loop {
            match self.at(0) {
                None | Some(b'\n') => {
                    self.error_at(start, "Unterminated quoted value".to_string());
                    return;
                }
                Some(b'\'') => {
                    self.pos += 1;
                    return;
                }
                Some(c) => {
                    let len = utf8_len(c);
                    text.push_str(&self.src[self.pos..self.pos + len]);
                    self.pos += len;
                }
            }
        }
    }

    fn scan_quoted(&mut self, text: &mut String) {
        let start = self.pos;
        self.pos += 1; // opening quote
        loop {
            match self.at(0) {
                None | Some(b'\n') => {
                    self.error_at(start, "Unterminated quoted value".to_string());
                    return;
                }
                Some(b'"') => {
                    self.pos += 1;
                    return;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escaped = match self.at(0) {
                        Some(b'n') => '\n',
                        Some(b't') => '\t',
                        Some(b'r') => '\r',
                        Some(c @ (b'"' | b'\\')) => c as char,
                        Some(c) => {
                            self.error_at(self.pos, format!("Unknown escape '\\{}'", c as char));
                            c as char
                        }
                        None => continue,
                    };
                    text.push(escaped);
                    self.pos += 1;
                }
                Some(c) => {
                    let len = utf8_len(c);
                    text.push_str(&self.src[self.pos..self.pos + len]);
                    self.pos += len;
                }
            }
        }
    }

    pub fn read_word(&mut self) -> Option<Word> {
        self.scan_word(false)
    }

    /// The key of a setting: a word that ends at the first unquoted `=`.
    pub fn read_key(&mut self) -> Option<Word> {
        self.scan_word(true)
    }

    /// Remember a position, to `reset` back to it. Used for the one place that needs a look-ahead:
    /// deciding whether the next word ends the current statement.
    pub fn mark(&self) -> usize {
        self.pos
    }

    pub fn reset(&mut self, mark: usize) {
        self.pos = mark;
    }

    pub fn read_eq(&mut self) -> bool {
        self.skip_blank();
        if self.at(0) == Some(b'=') {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// The raw rest of the line, for values handed to a shell verbatim so their own quoting
    /// survives. A word-starting `#` still ends it, and so does a closing brace at the very end,
    /// so that a whole block still fits on one line (`process { command = sleep 1 }`).
    pub fn read_rest_of_line(&mut self) -> String {
        self.skip_blank();
        let start = self.pos;
        let mut end = self.pos;
        loop {
            match self.at(0) {
                None | Some(b'\n') => break,
                Some(b'#') if self.pos == start || matches!(self.bytes[self.pos - 1], b' ' | b'\t') => break,
                Some(b' ') | Some(b'\t') | Some(b'\r') => self.pos += 1,
                Some(c) => {
                    self.pos += utf8_len(c);
                    end = self.pos;
                }
            }
        }

        // Give back a trailing `}` so the enclosing block can close. It only counts as structure
        // when it stands alone, exactly as it does everywhere else.
        let text = &self.src[start..end];
        if let Some(trimmed) = text.strip_suffix('}') {
            if trimmed.is_empty() || trimmed.ends_with([' ', '\t']) {
                self.pos = start + trimmed.len();
                return trimmed.trim_end().to_string();
            }
        }
        text.to_string()
    }

    /// Error recovery: drop whatever is left of the current line.
    pub fn skip_line(&mut self) {
        while !matches!(self.at(0), None | Some(b'\n')) {
            self.pos += 1;
        }
    }

    pub fn error(&mut self, message: String) {
        let pos = self.pos;
        self.error_at(pos, message);
    }

    pub fn error_at(&mut self, pos: usize, message: String) {
        let (line, col) = self.line_col(pos);
        self.errors.push(Diagnostic { line, col, message });
    }

    fn line_col(&self, pos: usize) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;
        for &c in &self.bytes[..pos.min(self.bytes.len())] {
            if c == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }
}

fn utf8_len(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Whether `name` can be the name of a `name=value` argument. Anything that looks like one is
/// treated as one - an unknown name is then reported rather than quietly taken as a positional
/// argument that happens to contain an `=`. A value that really contains an `=` is quoted:
/// `set_header Cache-Control "max-age=60"`.
pub fn is_argument_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
