// Tiny dependency-free JSON parser (objects/arrays/strings/numbers/bool/null) — enough for the flat
// target files. Plus a `Target` accessor with the hx()/int coercion the orchestrator needs.
#![allow(dead_code)]
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn parse(s: &str) -> Result<Json, String> {
        let b = s.as_bytes();
        let mut p = P { b, i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != b.len() { return Err(format!("trailing data at {}", p.i)); }
        Ok(v)
    }
    pub fn get(&self, k: &str) -> Option<&Json> {
        if let Json::Obj(m) = self { m.get(k) } else { None }
    }
    pub fn as_str(&self) -> Option<&str> { if let Json::Str(s) = self { Some(s) } else { None } }
    pub fn as_bool(&self) -> Option<bool> { if let Json::Bool(b) = self { Some(*b) } else { None } }
    pub fn as_f64(&self) -> Option<f64> { if let Json::Num(n) = self { Some(*n) } else { None } }
}

struct P<'a> { b: &'a [u8], i: usize }
impl<'a> P<'a> {
    fn ws(&mut self) { while self.i < self.b.len() && matches!(self.b[self.i], b' '|b'\t'|b'\n'|b'\r') { self.i += 1; } }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => self.obj(),
            Some(b'[') => self.arr(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => { self.lit("true")?; Ok(Json::Bool(true)) }
            Some(b'f') => { self.lit("false")?; Ok(Json::Bool(false)) }
            Some(b'n') => { self.lit("null")?; Ok(Json::Null) }
            Some(_) => self.num(),
            None => Err("unexpected EOF".into()),
        }
    }
    fn lit(&mut self, s: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(s.as_bytes()) { self.i += s.len(); Ok(()) }
        else { Err(format!("expected {} at {}", s, self.i)) }
    }
    fn obj(&mut self) -> Result<Json, String> {
        self.i += 1; let mut m = BTreeMap::new(); self.ws();
        if self.b.get(self.i) == Some(&b'}') { self.i += 1; return Ok(Json::Obj(m)); }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') { return Err(format!("expected : at {}", self.i)); }
            self.i += 1;
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => { self.i += 1; }
                Some(b'}') => { self.i += 1; break; }
                _ => return Err(format!("expected , or }} at {}", self.i)),
            }
        }
        Ok(Json::Obj(m))
    }
    fn arr(&mut self) -> Result<Json, String> {
        self.i += 1; let mut v = Vec::new(); self.ws();
        if self.b.get(self.i) == Some(&b']') { self.i += 1; return Ok(Json::Arr(v)); }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => { self.i += 1; }
                Some(b']') => { self.i += 1; break; }
                _ => return Err(format!("expected , or ] at {}", self.i)),
            }
        }
        Ok(Json::Arr(v))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') { return Err(format!("expected string at {}", self.i)); }
        self.i += 1;
        let mut s = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("bad escape")?; self.i += 1;
                    match e {
                        b'"' => s.push('"'), b'\\' => s.push('\\'), b'/' => s.push('/'),
                        b'n' => s.push('\n'), b't' => s.push('\t'), b'r' => s.push('\r'),
                        b'b' => s.push('\u{08}'), b'f' => s.push('\u{0c}'),
                        b'u' => {
                            let h = std::str::from_utf8(&self.b[self.i..self.i+4]).map_err(|_| "bad \\u")?;
                            let cp = u32::from_str_radix(h, 16).map_err(|_| "bad \\u")?;
                            self.i += 4;
                            s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => s.push(c as char),
            }
        }
        Err("unterminated string".into())
    }
    fn num(&mut self) -> Result<Json, String> {
        let start = self.i;
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b'0'..=b'9'|b'-'|b'+'|b'.'|b'e'|b'E') { self.i += 1; } else { break; }
        }
        let t = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad num")?;
        t.parse::<f64>().map(Json::Num).map_err(|_| format!("bad number '{}'", t))
    }
}

/// Coerce a Json field to i64: accepts "0x..", decimal string, or a JSON number.
pub fn hx(v: &Json) -> Option<i64> {
    match v {
        Json::Str(s) => {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                i64::from_str_radix(h, 16).ok().or_else(|| u64::from_str_radix(h, 16).ok().map(|u| u as i64))
            } else { s.parse::<i64>().ok() }
        }
        Json::Num(n) => Some(*n as i64),
        _ => None,
    }
}
