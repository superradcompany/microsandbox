//! Existing JSON and revision-fenced control requests.
use super::handler::ControlContext;
use crate::control::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn respond_to_line(line: &str, context: &ControlContext) -> Vec<u8> {
    respond_with_memory(line, context, None)
}

pub(super) fn respond_with_memory(
    line: &str,
    context: &ControlContext,
    memory: Option<std::fs::File>,
) -> Vec<u8> {
    let value = serde_json::from_str::<serde_json::Value>(line);
    let mut payload = match value {
        Ok(value) if value.get("protocol_version").is_some() => {
            match serde_json::from_value::<ControlEnvelope>(value) {
                Ok(envelope)
                    if memory.is_none()
                        && !matches!(
                            envelope.command,
                            ControlRequest::BranchCreateMemfd { .. }
                        ) =>
                {
                    serde_json::to_vec(&context.executor.execute(envelope))
                }
                Ok(_) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error: Some("descriptor handoff requires a one-shot branch request".into()),
                    ..Default::default()
                }),
                Err(error) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error_code: Some("invalid_envelope".into()),
                    error: Some(format!("invalid control envelope: {error}")),
                    ..Default::default()
                }),
            }
        }
        Ok(value) => match serde_json::from_value::<ControlRequest>(value) {
            Ok(mut request) => match attach_branch_memory(&mut request, memory) {
                Ok(()) => serde_json::to_vec(&context.executor.execute_legacy(request)),
                Err(error) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error: Some(error.to_string()),
                    ..Default::default()
                }),
            },
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

fn attach_branch_memory(
    request: &mut ControlRequest,
    memory: Option<std::fs::File>,
) -> std::io::Result<()> {
    match (request, memory) {
        (ControlRequest::BranchCreateMemfd { backing, .. }, Some(file)) => {
            #[cfg(target_os = "linux")]
            {
                crate::memory_handoff::validate_empty(&file)?;
                *backing = Some(std::sync::Arc::new(file));
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (backing, file);
                Err(std::io::Error::other("memory descriptors require Linux"))
            }
        }
        (ControlRequest::BranchCreateMemfd { .. }, None) => {
            Err(std::io::Error::other("missing branch memory descriptor"))
        }
        (_, Some(_)) => Err(std::io::Error::other("unexpected control descriptor")),
        (_, None) => Ok(()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_operation_requires_transport_ownership() {
        let mut request: ControlRequest = serde_json::from_str(r#"{"op":"branch_create_memfd","branch_id":"branch_test","child_name":"child","memory_cache_dir":"/cache"}"#).unwrap();
        assert!(attach_branch_memory(&mut request, None).is_err());
        let old: ControlCapabilities = serde_json::from_str(r#"{"cpu_resize":false,"memory_resize":false,"secrets_update":false,"branch_create":true}"#).unwrap();
        assert!(!old.branch_memfd);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_branch_requests_accept_fresh_memory() {
        let mut branch: ControlRequest = serde_json::from_str(r#"{"op":"branch_create_memfd","branch_id":"branch_test","child_name":"child","memory_cache_dir":"/cache"}"#).unwrap();
        let memory = crate::memory_handoff::create().unwrap();
        attach_branch_memory(&mut branch, Some(memory)).unwrap();
        assert!(matches!(
            branch,
            ControlRequest::BranchCreateMemfd {
                backing: Some(_),
                ..
            }
        ));
        let mut other = ControlRequest::Capabilities;
        assert!(
            attach_branch_memory(&mut other, Some(crate::memory_handoff::create().unwrap()))
                .is_err()
        );
    }
}
