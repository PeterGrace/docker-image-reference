#[cfg(test)]
#[ctor::ctor]
fn init() { pretty_env_logger::init(); }

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;
    use crate::{FromStrExtended, Reference, Registry};

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
                        Err(format!("expected error `{:#?}`, got different error `{:#?}`", expected_err, err))
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
                input: "reg.gfpd.us/library/tolerable:test1",
                want: Ok((
                    Reference {
                        registry: Some(Registry { hostname: "reg.gfpd.us", port: None}),
                        name: "library/tolerable",
                        tag: Some("test1"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "ubuntu:test2",
                want: Ok((
                    Reference {
                        registry: None,
                        name: "ubuntu",
                        tag: Some("test2"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com/user-name/ubuntu:test3",
                want: Ok((
                    Reference {
                        registry: Some(Registry { hostname: "example.com", port: None }),
                        name: "user-name/ubuntu",
                        tag: Some("test3"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu:test4",
                want: Ok((
                    Reference {
                        registry: Some(Registry { hostname: "example.com", port: Some("8080") }),
                        name: "user-name/ubuntu",
                        tag: Some("test4"),
                        digest: None,
                    },
                    "",
                )),
            },
            Test {
                input: "example.com:8080/user-name/ubuntu",
                want: Ok((
                    Reference {
                        registry: Some(Registry { hostname: "example.com", port: Some("8080") }),
                        name: "user-name/ubuntu",
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
