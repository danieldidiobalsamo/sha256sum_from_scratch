///    This module defines a structure for variables named as "working variables" in SHA specification
///    It stores intermediary values for the compression function.
///    
///    All variables names in this module (a, b, ..., h) are the same as in the specification's formulas.

#[derive(Debug, PartialEq)]
pub struct WorkingVariables {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
    pub f: u32,
    pub g: u32,
    pub h: u32,
}

impl WorkingVariables {
    pub fn new(val: &[u32]) -> WorkingVariables {
        Self {
            a: val[0],
            b: val[1],
            c: val[2],
            d: val[3],
            e: val[4],
            f: val[5],
            g: val[6],
            h: val[7],
        }
    }

    pub fn iter(&self) -> Iter {
        Iter {
            inner: self,
            index: 0,
        }
    }

    pub fn update(&mut self, hash: &[u32]) {
        self.a = hash[0];
        self.b = hash[1];
        self.c = hash[2];
        self.d = hash[3];
        self.e = hash[4];
        self.f = hash[5];
        self.g = hash[6];
        self.h = hash[7];
    }
}

/// This structure allow to iterate over WorkingVariables fields
pub struct Iter<'a> {
    inner: &'a WorkingVariables,
    index: u8,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a u32;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.index {
            0 => &self.inner.a,
            1 => &self.inner.b,
            2 => &self.inner.c,
            3 => &self.inner.d,
            4 => &self.inner.e,
            5 => &self.inner.f,
            6 => &self.inner.g,
            7 => &self.inner.h,
            _ => return None,
        };
        self.index += 1;
        Some(ret)
    }
}
