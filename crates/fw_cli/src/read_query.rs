//! Bounded CLI read parameters. Authentication is still handled by the caller.
use crate::Result;

pub(crate) struct ReadQuery {
    pub route: &'static str,
    pub parameters: Vec<(String, String)>,
}
pub(crate) fn parse(args: &[String]) -> Result<ReadQuery> {
    let command = args.first().ok_or("one command is required")?.as_str();
    let (route, list) = match command {
        "health" => ("/healthz", false),
        "status" => ("/api/v1/status", false),
        "capabilities" => ("/api/v1/capabilities", false),
        "requests" => ("/api/v1/access-requests", true),
        "operations" => ("/api/v1/operations", true),
        "audit" => ("/api/v1/audit/events", true),
        "assets" => ("/api/v1/assets", true),
        "services" => ("/api/v1/services", true),
        "targets" => ("/api/v1/targets", true),
        "enrollments" => ("/api/v1/enrollments", true),
        _ => return Err("unknown command; see --help".into()),
    };
    if (!list && args.len() != 1) || args.len() > 5 || args.len().is_multiple_of(2) {
        return Err("list options require one --limit and/or --cursor value".into());
    }
    let mut parameters = Vec::new();
    for pair in args[1..].as_chunks::<2>().0 {
        let name = match pair[0].as_str() {
            "--limit" => {
                let limit: usize = pair[1].parse().map_err(|_| "limit must be from 1 to 100")?;
                if !(1..=100).contains(&limit) || limit.to_string() != pair[1] {
                    return Err("limit must be a canonical integer from 1 to 100".into());
                }
                "limit"
            }
            "--cursor" => {
                if pair[1].is_empty()
                    || pair[1].len() > 2048
                    || !pair[1]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err("cursor must be the bounded opaque value from next_cursor".into());
                }
                "cursor"
            }
            _ => return Err("unsupported list option; use --limit or --cursor".into()),
        };
        if parameters.iter().any(|(key, _)| key == name) {
            return Err("duplicate list option".into());
        }
        parameters.push((name.to_owned(), pair[1].clone()));
    }
    Ok(ReadQuery { route, parameters })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }
    #[test]
    fn bounded_continuation_is_a_query_not_a_route_or_authority_change() {
        let q = parse(&args(&["assets", "--cursor", "ab_12-Z", "--limit", "25"])).unwrap();
        assert_eq!(q.route, "/api/v1/assets");
        assert_eq!(
            q.parameters,
            vec![
                ("cursor".into(), "ab_12-Z".into()),
                ("limit".into(), "25".into())
            ]
        );
        for command in [
            "requests",
            "operations",
            "audit",
            "services",
            "targets",
            "enrollments",
        ] {
            assert!(parse(&args(&[command, "--limit", "100"])).is_ok());
        }
    }
    #[test]
    fn malformed_options_are_rejected_before_session_files_or_http_are_touched() {
        for values in [
            vec!["assets", "--limit", "0"],
            vec!["assets", "--limit", "101"],
            vec!["assets", "--limit", "01"],
            vec!["assets", "--limit", "1", "--limit", "2"],
            vec!["assets", "--cursor", "x&limit=100"],
            vec!["assets", "--cursor", "x%26limit=100"],
            vec!["assets", "--cursor", ""],
            vec!["assets", "--cursor"],
            vec!["assets", "--route", "https://other.example"],
            vec!["status", "--limit", "1"],
            vec!["health", "--cursor", "abc"],
            vec!["capabilities", "--limit", "1"],
            vec!["missing"],
        ] {
            assert!(parse(&args(&values)).is_err(), "{values:?}");
        }
        assert!(parse(&args(&["assets", "--cursor", &"a".repeat(2049)])).is_err());
        assert!(parse(&[]).is_err());
    }
}
