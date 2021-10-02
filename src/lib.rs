use anyhow::{bail, Result};
use const_format::concatcp;
use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

// Grammar -- from https://github.com/distribution/distribution/blob/v2.7.1/reference/reference.go
//
// reference        := name [ ":" tag ] [ "@" digest ]
// name             := [domain '/'] path-component ['/' path-component]*
// domain           := domain-component ['.' domain-component]* [':' port-number]
// domain-component := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
// port-number      := /[0-9]+/
// path-component   := alpha-numeric [separator alpha-numeric]*
// alpha-numeric    := /[a-z0-9]+/
// separator        := /[_.]|__|[-]*/
//
// tag              := /[\w][\w.-]{0,127}/
//
// digest                     := digest-algorithm ":" digest-hex
// digest-algorithm           := digest-algorithm-component [ digest-algorithm-separator digest-algorithm-component ]*
// digest-algorithm-separator := /[+.-_]/
// digest-algorithm-component := /[A-Za-z][A-Za-z0-9]*/
// digest-hex                 := /[0-9a-fA-F]{32,}/ ; At least 128 bit digest value

const NAME: &str = concatcp!("^(", DOMAIN, "/)?", PATH_COMPONENT, "(/", PATH_COMPONENT, ")*");
const DOMAIN: &str = concatcp!(DOMAIN_COMPONENT, r#"(\."#, DOMAIN_COMPONENT, ")*(:", PORT_NUMBER, ")?");
const DOMAIN_COMPONENT: &str = r#"([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"#;
const PORT_NUMBER: &str = r#"([0-9]+)"#;
const PATH_COMPONENT: &str = concatcp!(ALPHA_NUMERIC, "(", SEPARATOR, ALPHA_NUMERIC, ")*");
const ALPHA_NUMERIC: &str = r#"([a-z0-9]+)"#;
const SEPARATOR: &str = r#"([_\.]|__|[-]*)"#;

const COLON_TAG: &str = concatcp!("^:", TAG);
const TAG: &str = r#"([0-9A-Za-z_][0-9A-Za-z_\.-]{0,127})"#;

const AT_DIGEST: &str = concatcp!("^@", DIGEST);
const DIGEST: &str = concatcp!(DIGEST_ALGORITHM, ":", DIGEST_HEX);
const DIGEST_ALGORITHM: &str = concatcp!(
    DIGEST_ALGORITHM_COMPONENT,
    "(",
    DIGEST_ALGORITHM_SEPARATOR,
    DIGEST_ALGORITHM_COMPONENT,
    ")*"
);
const DIGEST_ALGORITHM_SEPARATOR: &str = r#"([\+\.-_])"#;
const DIGEST_ALGORITHM_COMPONENT: &str = r#"([A-Za-z][A-Za-z0-9]*)"#;
const DIGEST_HEX: &str = r#"([0-9a-fA-F]{32,})"#;

lazy_static! {
    static ref NAME_REGEX: Regex = Regex::new(NAME).unwrap();
    static ref COLON_TAG_REGEX: Regex = Regex::new(COLON_TAG).unwrap();
    static ref AT_DIGEST_REGEX: Regex = Regex::new(AT_DIGEST).unwrap();
}

/// Similar to regular FromStr but returns unused trailing characters.
trait FromStrExtended<'a>: Sized {
    fn from_str_ext(s: &'a str) -> Result<(Self, &'a str)>;
}

/// A reference to a docker image, e.g. `ubuntu:20.04` or `localhost:5000/example:1.0-dev`.
///
/// [`Reference::from_str()`] can be used to parse an image reference following the grammar
/// specified in <https://github.com/distribution/distribution/blob/v2.7.1/reference/reference.go>.
///
/// In short, a reference is of the form `name [':' tag] ['@' digest]`, where `tag` and `digest`
/// parts are optional. More information on the grammar can be found in the link above.
///
/// Note that no semantic check is performed, e.g. whether the port number is too long, etc.
/// However it should be able to correctly parse the `name`, `tag` and `digest` components of a
/// reference.
///
/// [`Reference::from_str()`]: #method.from_str
#[derive(PartialEq)]
pub struct Reference<'r> {
    name: &'r str,
    tag: Option<&'r str>,
    digest: Option<Digest<'r>>,
}

impl<'r> Reference<'r> {
    /// Parse a reference string.
    ///
    /// For example:
    /// ```
    /// use docker_image_reference::Reference;
    /// let r = Reference::from_str("ubuntu:20.04").unwrap();
    /// assert_eq!(r.name(), "ubuntu");
    /// assert_eq!(r.tag(), Some("20.04"));
    /// ```
    pub fn from_str(s: &'r str) -> Result<Self> {
        Reference::from_str_ext(s).map(|(r, _)| r)
    }

    /// Get the name component of the reference. This might start with a `host[:port]` part
    /// followed by one or more path components separated by slash.
    ///
    /// For example:
    /// ```
    /// use docker_image_reference::Reference;
    /// let r = Reference::from_str("index.docker.io/library/ubuntu:latest").unwrap();
    /// assert_eq!(r.name(), "index.docker.io/library/ubuntu");
    /// ```
    pub fn name(&self) -> &'r str {
        self.name
    }

    /// Get the tag component if present. This is a sequence of up to 128 alphanumerics,
    /// `-`, `.` and `_` not starting with `.` or `-`.
    ///
    /// For example:
    /// ```
    /// use docker_image_reference::Reference;
    /// let r = Reference::from_str("example:1.2.3-dev_test").unwrap();
    /// assert_eq!(r.tag(), Some("1.2.3-dev_test"));
    /// ```
    pub fn tag(&self) -> Option<&'r str> {
        self.tag
    }

    /// Returns true if the reference contains a digest component.
    /// If this function returns true, then both [`digest_algorithm()`] and [`digest_hex()`]
    /// will return `Some`.
    ///
    /// For example:
    /// ```
    /// use docker_image_reference::Reference;
    /// let r = Reference::from_str("image-name@sha256:9d78ad0da0e88ca15da5735b9f70064d3099ac0a8cd9dc839795789400a38e42").unwrap();
    /// assert!(r.has_digest());
    /// assert_eq!(r.digest_algorithm(), Some("sha256"));
    /// assert_eq!(r.digest_hex(), Some("9d78ad0da0e88ca15da5735b9f70064d3099ac0a8cd9dc839795789400a38e42"));
    /// ```
    ///
    /// [`digest_algorithm()`]: #method.digest_algorithm
    /// [`digest_hex()`]: #method.digest_hex
    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }

    pub fn digest_algorithm(&self) -> Option<&'r str> {
        self.digest.as_ref().map(|d| d.algorithm)
    }

    pub fn digest_hex(&self) -> Option<&'r str> {
        self.digest.as_ref().map(|d| d.digest_hex)
    }
}

impl<'a> FromStrExtended<'a> for Reference<'a> {
    fn from_str_ext(s: &'a str) -> Result<(Self, &'a str)> {
        let (name, s) = match NAME_REGEX.find(s) {
            Some(m) => (m.as_str(), &s[m.end()..]),
            None => bail!("no name found in `{}`", s),
        };
        let (tag, s) = match s.chars().next() {
            Some(':') => {
                let (tag, s) = Tag::from_str_ext(s)?;
                (Some(tag.0), s)
            }
            _ => (None, s),
        };
        let (digest, s) = match s.chars().next() {
            Some('@') => {
                let (digest, s) = Digest::from_str_ext(s)?;
                (Some(digest), s)
            }
            _ => (None, s),
        };
        if s != "" {
            bail!("unrecognized trailing characters: `{}`", s);
        }
        Ok((Reference { name, tag, digest }, ""))
    }
}

impl<'r> fmt::Display for Reference<'r> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref tag) = self.tag {
            write!(f, ":{}", tag)?;
        }
        if let Some(ref digest) = self.digest {
            write!(f, "@{}:{}", digest.algorithm, digest.digest_hex)?;
        }
        Ok(())
    }
}

struct Tag<'r>(&'r str);

impl<'a> FromStrExtended<'a> for Tag<'a> {
    fn from_str_ext(s: &'a str) -> Result<(Self, &'a str)> {
        let (colon_tag, s) = match COLON_TAG_REGEX.find(s) {
            Some(m) => (m.as_str(), &s[m.end()..]),
            None => bail!("no tag found in `{}`", s),
        };
        let tag = colon_tag.strip_prefix(":").expect("colon at the begining");
        Ok((Tag(tag), s))
    }
}

#[derive(PartialEq)]
struct Digest<'r> {
    algorithm: &'r str,
    digest_hex: &'r str,
}

impl<'a> FromStrExtended<'a> for Digest<'a> {
    fn from_str_ext(s: &'a str) -> Result<(Self, &'a str)> {
        let (at_digest, s) = match AT_DIGEST_REGEX.find(s) {
            Some(m) => (m.as_str(), &s[m.end()..]),
            None => bail!("no digest found in `{}`", s),
        };
        let mut split = at_digest.strip_prefix("@").expect("@ at the begining").split(":");
        let (algorithm, digest_hex) = match (split.next(), split.next()) {
            (Some(algorithm), Some(digest_hex)) => (algorithm, digest_hex),
            _ => unreachable!(),
        };
        Ok((Digest { algorithm, digest_hex }, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;

    struct Test<'t, T> {
        input: &'t str,
        want: Result<(T, &'t str), String>,
    }

    impl<'t, T: FromStrExtended<'t> + PartialEq + Display> Test<'t, T> {
        fn run(self) -> Result<(), String> {
            let res = T::from_str_ext(self.input);
            match (self.want, res) {
                (Ok((expected_value, expected_unused)), Ok((value, unused))) => {
                    if value == expected_value && unused == expected_unused {
                        Ok(())
                    } else {
                        let mut err = String::new();
                        if value != expected_value {
                            err.push_str(&format!("expected value `{}` got `{}`. ", expected_value, value));
                        }
                        if unused != expected_unused {
                            err.push_str(&format!("expected unused `{}` got `{}`.", expected_unused, unused));
                        }
                        Err(err)
                    }
                }
                (Err(expected_err), Err(err)) => {
                    if expected_err == err.to_string() {
                        Ok(())
                    } else {
                        Err(format!("expected error `{}`, got different error `{}`", expected_err, err))
                    }
                }
                (Ok(_), Err(_)) => Err(format!("expected ok, got error")),
                (Err(_), Ok(_)) => Err(format!("expected error, got ok")),
            }
        }
    }

    #[test]
    fn reference_grammar() {
        let tests = vec![
            Test {
                input: "ubuntu:16.04",
                want: Ok((
                    Reference {
                        name: "ubuntu",
                        tag: Some("16.04"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com/user-name/ubuntu:16.04-lts",
                want: Ok((
                    Reference {
                        name: "example.com/user-name/ubuntu",
                        tag: Some("16.04-lts"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu:16.04-lts",
                want: Ok((
                    Reference {
                        name: "example.com:8080/user-name/ubuntu",
                        tag: Some("16.04-lts"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu",
                want: Ok((
                    Reference {
                        name: "example.com:8080/user-name/ubuntu",
                        tag: None,
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com:8080/user___name/ubuntu",
                want: Err("unrecognized trailing characters: `___name/ubuntu`".to_owned()),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu:φ",
                want: Err("no tag found in `:φ`".to_owned()),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu@φ",
                want: Err("no digest found in `@φ`".to_owned()),
            },
            Test {
                input: "αβγδ",
                want: Err("no name found in `αβγδ`".to_owned()),
            },
        ];

        for t in tests {
            match t.run() {
                Ok(()) => {}
                Err(e) => panic!("{}", e),
            }
        }
    }

    #[test]
    fn public_api() {
        let r = Reference::from_str("user/image:tag").unwrap();
        assert_eq!(r.name(), "user/image");
        assert_eq!(r.tag(), Some("tag"));
        assert_eq!(r.digest_algorithm(), None);
        assert_eq!(r.digest_hex(), None);
        assert_eq!(r.to_string(), "user/image:tag".to_owned());

        let r = Reference::from_str("user/image:1.2.3-abc@sha256:9d78ad0da0e88ca15da5735b9f70064d3099ac0a8cd9dc839795789400a38e42").unwrap();
        assert_eq!(r.name(), "user/image");
        assert_eq!(r.tag(), Some("1.2.3-abc"));
        assert_eq!(r.digest_algorithm(), Some("sha256"));
        assert_eq!(r.digest_hex(), Some("9d78ad0da0e88ca15da5735b9f70064d3099ac0a8cd9dc839795789400a38e42"));
        assert_eq!(
            r.to_string(),
            "user/image:1.2.3-abc@sha256:9d78ad0da0e88ca15da5735b9f70064d3099ac0a8cd9dc839795789400a38e42".to_owned()
        );
    }
}
