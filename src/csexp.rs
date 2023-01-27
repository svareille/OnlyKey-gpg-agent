//! Canonical S-Expressions are defined here: [https://people.csail.mit.edu/rivest/Sexp.txt]

use thiserror::Error;

#[derive(Error, Debug)]
#[derive(PartialEq)]
pub enum SexpError<'a> {
    #[error("More data than needed to form an S-Expression")]
    MoreData(Sexp, &'a [u8]),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Sexp {
    Atom(Vec<u8>),
    List(Vec<Sexp>),
}

impl Sexp {

    /// Parse input, returning an [Sexp::Atom] and the rest of the expression
    fn parse_atom(s: &[u8]) -> Result<Sexp, SexpError> {
        let (size, s) = {
            let mut split = s.splitn(2, |&e| e == b':');
            match split.next() {
                Some(item) => (
                    std::str::from_utf8(item).ok().and_then(|item| item.parse::<usize>().ok() ).ok_or_else(||SexpError::InvalidFormat("Atom's first part is not a number".to_owned()))?,
                    split.next().ok_or_else(||SexpError::InvalidFormat("Atom's second part is empty".to_owned()))?),
                None => return Err(SexpError::InvalidFormat("Input is empty".to_owned())),
            }
            
        };
        let atom = Sexp::Atom(s[..size].to_vec());
        let s = &s[size..];
        if s.is_empty() {
            Ok(atom)
        } else {
            Err(SexpError::MoreData(atom, s))
        }
    }

    pub fn parse(mut s: &[u8]) -> Result<Sexp, SexpError> {
        if s.starts_with(b"(") {
            // Sexp is a list
            let mut sexprs = Vec::new();

            s = &s[1..]; // Remove the opening parenthese

            while !s.starts_with(b")") {
                // Inside the list: 0 or more sexp
                s = match Sexp::parse(s) {
                    Err(SexpError::MoreData(exp, s)) => {
                        sexprs.push(exp);
                        s
                    }
                    Ok(_) => {
                        // Should never reach that: it means that the S-Exp is ill-formed,
                        // missing closing parenthese.
                        return Err(SexpError::InvalidFormat("Unexpected EOF".to_owned()));
                    }
                    Err(SexpError::InvalidFormat(s)) => {
                        return Err(SexpError::InvalidFormat(s));
                    }
                }
            }

            s = &s[1..]; // Remove the closing parenthese

            if s.is_empty() {
                Ok(Sexp::List(sexprs))
            } else {
                Err(SexpError::MoreData(Sexp::List(sexprs), s))
            }
        } else {
            // Sexp is an Atom, potentially followed by (several) Sexp
            Sexp::parse_atom(s)
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match &self {
            Sexp::Atom(data) => {
                let mut exp = Vec::new();
                exp.extend_from_slice(data.len().to_string().as_bytes());
                exp.push(b':');
                exp.extend_from_slice(data);
                exp
            },
            Sexp::List(exps) => {
                let mut res = vec![b'('];
                for exp in exps {
                    res.append(&mut exp.to_vec());
                }
                res.push(b')');
                res
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::csexp::{Sexp, SexpError};

    #[test]
    fn parse_atom() {
        let s = b"6:azerty";
        let expected = Sexp::Atom(b"azerty".to_vec());
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_atom_nonascii() {
        let s = b"4:\x00\x01\x02\x03";
        let expected = Sexp::Atom(b"\x00\x01\x02\x03".to_vec());
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_atom_empty() {
        let s = b"0:";
        let expected = Sexp::Atom(b"".to_vec());
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_list_nonascii() {
        let s = b"(4:\x00\x01\x02\x031:\x00)";
        let expected = Sexp::List(vec![
            Sexp::Atom(b"\x00\x01\x02\x03".to_vec()),
            Sexp::Atom(b"\0".to_vec()),
        ]);
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_list_with_empty() {
        let s = b"(4:\x00\x01\x02\x030:1:\x00)";
        let expected = Sexp::List(vec![
            Sexp::Atom(b"\x00\x01\x02\x03".to_vec()),
            Sexp::Atom(b"".to_vec()),
            Sexp::Atom(b"\0".to_vec()),
        ]);
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_simple() {
        let s = b"(7:enc-val(4:ecdh(1:s10:abcdefghij)(1:e5:12345)))";
        let expected = Sexp::List(vec![
            Sexp::Atom(b"enc-val".to_vec()),
            Sexp::List(vec![
                Sexp::Atom(b"ecdh".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"s".to_vec()),
                    Sexp::Atom(b"abcdefghij".to_vec()),
                ]),
                Sexp::List(vec![
                    Sexp::Atom(b"e".to_vec()),
                    Sexp::Atom(b"12345".to_vec()),
                ])
            ]),
        ]);
        assert_eq!(Sexp::parse(s), Ok(expected));
    }

    #[test]
    fn parse_wrong_parenthese() {
        let s = b"(7:enc-val(4:ecdh(1:s10:abcdefghij)(1:e5:12345)";
        assert_eq!(Sexp::parse(s), Err(SexpError::InvalidFormat("Unexpected EOF".to_owned())));
    }

    #[test]
    fn parse_more_data() {
        let s = b"(4:abcd2:12)more data";
        let exp = Sexp::List(vec![
            Sexp::Atom(b"abcd".to_vec()),
            Sexp::Atom(b"12".to_vec()),
        ]);
        assert_eq!(Sexp::parse(s), Err(SexpError::MoreData(exp, b"more data")));
    }

    #[test]
    fn parse_list_no_parenthese() {
        let s = b"4:abcd2:12";
        let exp = Sexp::Atom(b"abcd".to_vec());
        assert_eq!(Sexp::parse(s), Err(SexpError::MoreData(exp, b"2:12")));
    }

    #[test]
    fn serialize_atom() {
        let expected = b"6:azerty".to_vec();
        let s = Sexp::Atom(b"azerty".to_vec());
        assert_eq!(s.to_vec(), expected);
    }

    #[test]
    fn serialize_atom_nonascii() {
        let expected = b"4:\x00\x01\x02\x03".to_vec();
        let s = Sexp::Atom(b"\x00\x01\x02\x03".to_vec());
        assert_eq!(s.to_vec(), expected);
    }

    #[test]
    fn serialize_atom_empty() {
        let expected = b"0:".to_vec();
        let s = Sexp::Atom(b"".to_vec());
        assert_eq!(s.to_vec(), expected);
    }

    #[test]
    fn serialize_list_nonascii() {
        let expected = b"(4:\x00\x01\x02\x031:\x00)".to_vec();
        let s = Sexp::List(vec![
            Sexp::Atom(b"\x00\x01\x02\x03".to_vec()),
            Sexp::Atom(b"\0".to_vec()),
        ]);
        assert_eq!(s.to_vec(), expected);
    }

    #[test]
    fn serialize_list_with_empty() {
        let expected = b"(4:\x00\x01\x02\x030:1:\x00)".to_vec();
        let s = Sexp::List(vec![
            Sexp::Atom(b"\x00\x01\x02\x03".to_vec()),
            Sexp::Atom(b"".to_vec()),
            Sexp::Atom(b"\0".to_vec()),
        ]);
        assert_eq!(s.to_vec(), expected);
    }

    #[test]
    fn serialize_simple() {
        let expected = b"(7:enc-val(4:ecdh(1:s10:abcdefghij)(1:e5:12345)))".to_vec();
        let s = Sexp::List(vec![
            Sexp::Atom(b"enc-val".to_vec()),
            Sexp::List(vec![
                Sexp::Atom(b"ecdh".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"s".to_vec()),
                    Sexp::Atom(b"abcdefghij".to_vec()),
                ]),
                Sexp::List(vec![
                    Sexp::Atom(b"e".to_vec()),
                    Sexp::Atom(b"12345".to_vec()),
                ])
            ]),
        ]);
        assert_eq!(s.to_vec(), expected);
    }
}