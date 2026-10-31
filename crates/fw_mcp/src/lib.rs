//! Read-only MCP JSON-RPC transport core. Callers must authenticate before dispatch.
use serde_json::{Value, json};
pub const VERSION: &str = "2025-03-26";
pub fn tools() -> Value {
    json!([
     {"name":"get_capabilities","description":"Read verified and unavailable capabilities; does not authorize deployment","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
     {"name":"get_operation","description":"Read an operation in the authenticated project","inputSchema":{"type":"object","properties":{"operation_id":{"type":"string","format":"uuid"}},"required":["operation_id"],"additionalProperties":false}},
     {"name":"get_audit_events","description":"Read a bounded audit snapshot page in the authenticated project; follow next_cursor for remaining events","inputSchema":{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100},"after_sequence":{"type":"string","pattern":"^(0|[1-9][0-9]{0,19})$","maxLength":20},"cursor":{"type":"string","minLength":1,"maxLength":2048,"pattern":"^[A-Za-z0-9_-]+$"}},"additionalProperties":false}}
    ])
}
fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn valid_audit_arguments(arguments: &Value) -> bool {
    arguments.as_object().is_some_and(|fields| {
        fields.iter().all(|(name, value)| match name.as_str() {
            "limit" => value.as_u64().is_some_and(|n| (1..=100).contains(&n)),
            "after_sequence" => value.as_str().is_some_and(|s| {
                s.len() <= 20 && s.parse::<u64>().is_ok_and(|n| n.to_string() == s)
            }),
            "cursor" => value.as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 2048
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            }),
            _ => false,
        })
    })
}
pub fn dispatch<F>(request: Value, mut call: F) -> Option<Value>
where
    F: FnMut(&str, &Value) -> Result<Value, &'static str>,
{
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc") != Some(&json!("2.0"))
        || !request.is_object()
        || request.as_object().is_some_and(|m| {
            m.keys()
                .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
        })
    {
        return Some(error(id, -32600, "Invalid Request"));
    }
    if !id.is_null() && !id.is_string() && !id.is_i64() && !id.is_u64() {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "notifications/initialized" && id.is_null() {
        return None;
    }
    if id.is_null() {
        return Some(error(id, -32600, "Request id required"));
    }
    let params = request.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":VERSION,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"Nox Warden development","version":env!("CARGO_PKG_VERSION")},"instructions":"Authenticated read-only evidence. Native enforcement is unqualified. No approval, trust mutation, or deployment tools are available."})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":tools()}),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            let valid = match name {
                "get_capabilities" => arguments == json!({}),
                "get_audit_events" => valid_audit_arguments(&arguments),
                "get_operation" => arguments.as_object().is_some_and(|m| {
                    m.len() == 1 && m.get("operation_id").is_some_and(Value::is_string)
                }),
                _ => false,
            };
            if !valid {
                return Some(error(id, -32602, "Unknown tool or invalid arguments"));
            }
            match call(name, &arguments) {
                Ok(value) => {
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                }
                Err(code) => json!({"content":[{"type":"text","text":code}],"isError":true}),
            }
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn privileged_tools_never_dispatch() {
        let r=dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_deployment","arguments":{}}}),|_,_|panic!("must not dispatch")).unwrap();
        assert_eq!(r["error"]["code"], -32602);
    }
    #[test]
    fn reads_return_shared_evidence() {
        let r=dispatch(json!({"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"get_capabilities"}}),|name,_|{assert_eq!(name,"get_capabilities");Ok(json!({"enforcement":false}))}).unwrap();
        assert_eq!(r["result"]["structuredContent"]["enforcement"], false);
    }
    #[test]
    fn protocol_initializes() {
        let r = dispatch(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            |_, _| unreachable!(),
        )
        .unwrap();
        assert_eq!(r["result"]["protocolVersion"], VERSION);
        assert!(
            dispatch(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                |_, _| unreachable!()
            )
            .is_none()
        );
    }

    #[test]
    fn audit_pagination_accepts_bounded_canonical_arguments_only() {
        for args in [
            json!({}),
            json!({"limit":25,"after_sequence":"0"}),
            json!({"limit":100,"after_sequence":"18446744073709551615","cursor":"opaque_token-123"}),
        ] {
            let expected = args.clone();
            let result=dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_audit_events","arguments":args}}),|name,actual| {
                assert_eq!(name,"get_audit_events");assert_eq!(*actual,expected);
                Ok(json!({"data":[],"next_cursor":null}))
            }).unwrap();
            assert_eq!(result["result"]["isError"], false);
        }
        for args in [
            json!({"limit":0}),
            json!({"limit":101}),
            json!({"limit":1.5}),
            json!({"after_sequence":1}),
            json!({"after_sequence":"01"}),
            json!({"after_sequence":"18446744073709551616"}),
            json!({"cursor":""}),
            json!({"cursor":"contains.dot"}),
            json!({"cursor":"a".repeat(2049)}),
            json!({"org_id":"other"}),
            json!([]),
        ] {
            let result=dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_audit_events","arguments":args}}),|_,_|panic!("invalid arguments must not dispatch")).unwrap();
            assert_eq!(result["error"]["code"], -32602);
        }
    }
}
