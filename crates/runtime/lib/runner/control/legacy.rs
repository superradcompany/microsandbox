//! Existing JSON and revision-fenced control requests.
use super::handler::ControlContext;
use crate::control::*;

pub(super) fn respond_to_line(line: &str, context: &ControlContext) -> Vec<u8> {
    let value = serde_json::from_str::<serde_json::Value>(line);
    let mut payload = match value {
        Ok(value) if value.get("protocol_version").is_some() => {
            match serde_json::from_value::<ControlEnvelope>(value) {
                Ok(envelope) => serde_json::to_vec(&context.executor.execute(envelope)),
                Err(error) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error_code: Some("invalid_envelope".into()),
                    error: Some(format!("invalid control envelope: {error}")),
                    ..Default::default()
                }),
            }
        }
        Ok(value) => match serde_json::from_value::<ControlRequest>(value) {
            Ok(request) => serde_json::to_vec(&context.executor.execute_legacy(request)),
            Err(error) => serde_json::to_vec(&ControlResponse {
                ok: false,
                error_code: Some("invalid_request".into()),
                error: Some(format!("invalid control request: {error}")),
                ..Default::default()
            }),
        },
        Err(error) => serde_json::to_vec(&ControlResponse {
            ok: false,
            error_code: Some("invalid_json".into()),
            error: Some(format!("invalid control request: {error}")),
            ..Default::default()
        }),
    }
    .unwrap_or_default();
    payload.push(b'\n');
    payload
}
