//! Request-log redaction matching matterjs-server `packages/ws-client/src/logging-redaction.ts`
//! (v1.4.1-alpha.5, #1031). Door-lock PINs on the wire are base64 octstr, so logging the
//! payload writes the PIN in the clear.

use serde_json::{Map, Value as Json};

fn is_sensitive_payload_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "credentialdata" || lower == "pincode"
}

fn is_sensitive_arg_key(key: &str) -> bool {
    matches!(
        key,
        "credentials" | "dataset" | "password" | "thread_credentials"
    )
}

/// Return `message` unchanged when it carries no secret, otherwise a clone with sensitive
/// `args.payload` fields and Wi-Fi/Thread secrets replaced by `"[redacted]"`.
pub fn redact_sensitive_command_fields(message: &Json) -> Json {
    let Some(args) = message.get("args") else {
        return message.clone();
    };
    let mut redacted_args: Option<Map<String, Json>> = None;

    if let Some(payload) = args.get("payload").and_then(Json::as_object) {
        let secrets: Vec<String> = payload
            .keys()
            .filter(|k| is_sensitive_payload_key(k))
            .cloned()
            .collect();
        if !secrets.is_empty() {
            let mut payload = payload.clone();
            for k in secrets {
                payload.insert(k, Json::String("[redacted]".into()));
            }
            redacted_args
                .get_or_insert_with(|| args.as_object().cloned().unwrap_or_default())
                .insert("payload".into(), Json::Object(payload));
        }
    }

    if let Some(obj) = args.as_object() {
        for (k, _) in obj {
            if is_sensitive_arg_key(k) {
                redacted_args
                    .get_or_insert_with(|| obj.clone())
                    .insert(k.clone(), Json::String("[redacted]".into()));
            }
        }
    }

    match redacted_args {
        None => message.clone(),
        Some(args) => {
            let mut out = message.clone();
            if let Some(map) = out.as_object_mut() {
                map.insert("args".into(), Json::Object(args));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pin_code_any_case_is_redacted() {
        let msg = json!({"command":"device_command","args":{"payload":{"PINCode":"MTIzNA=="}}});
        let out = redact_sensitive_command_fields(&msg);
        assert_eq!(out["args"]["payload"]["PINCode"], "[redacted]");
        assert_eq!(msg["args"]["payload"]["PINCode"], "MTIzNA==");
    }

    #[test]
    fn credential_data_is_redacted() {
        let msg = json!({"args":{"payload":{"credentialData":"secret"}}});
        let out = redact_sensitive_command_fields(&msg);
        assert_eq!(out["args"]["payload"]["credentialData"], "[redacted]");
    }

    #[test]
    fn wifi_credentials_are_redacted() {
        let msg = json!({"command":"set_wifi_credentials","args":{"ssid":"x","credentials":"hunter2"}});
        let out = redact_sensitive_command_fields(&msg);
        assert_eq!(out["args"]["credentials"], "[redacted]");
        assert_eq!(out["args"]["ssid"], "x");
    }

    #[test]
    fn harmless_command_is_unchanged() {
        let msg = json!({"command":"get_nodes","args":{"only_available":true}});
        assert_eq!(redact_sensitive_command_fields(&msg), msg);
    }
}
