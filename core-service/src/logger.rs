use serde_json::{Map, Value, json};

pub fn info(event: &str, trace_id: Option<&str>, fields: Value) {
    log("info", event, trace_id, fields);
}

pub fn warn(event: &str, trace_id: Option<&str>, fields: Value) {
    log("warn", event, trace_id, fields);
}

pub fn error(event: &str, trace_id: Option<&str>, fields: Value) {
    log("error", event, trace_id, fields);
}

pub fn error_message(event: &str, trace_id: Option<&str>, err: impl ToString) {
    error(event, trace_id, json!({ "error": err.to_string() }));
}

fn log(level: &str, event: &str, trace_id: Option<&str>, fields: Value) {
    let mut entry = Map::new();
    entry.insert("timestamp".to_string(), json!(crate::store::unix_now()));
    entry.insert("level".to_string(), json!(level));
    entry.insert("service".to_string(), json!("core-service"));
    entry.insert("event".to_string(), json!(event));
    entry.insert(
        "trace_id".to_string(),
        trace_id
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );

    match fields {
        Value::Object(map) => {
            for (key, value) in map {
                entry.insert(key, value);
            }
        }
        Value::Null => {}
        other => {
            entry.insert("details".to_string(), other);
        }
    }

    eprintln!("{}", Value::Object(entry));
}