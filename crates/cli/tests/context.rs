//! Context management must work without credentials, a backend connection, or a catalog.
//! Run on an unmanaged host; subprocesses retain system policy. See DEVELOPMENT.md.

use std::{
    path::Path,
    process::{Command, Output},
};

use serde_json::{Value, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn command(dir: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_msb"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MSB_") {
            command.env_remove(key);
        }
    }
    command
        .args(arguments)
        .env("MSB_CONFIG_PATH", dir.join("config.json"))
        .env("MSB_HOME", dir.join("runtime"))
        .env("NO_COLOR", "1");
    command
}

fn success_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn context_commands_recover_selection_and_save_only_the_preference() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = json!({
        "active_profile":"missing",
        "sandbox_defaults":{"cpus":3},
        "profiles":{
            "local":{"backend":"local"},
            "work":{"backend":"cloud","api_key_ref":"env:MSB_UNSET_CONTEXT_KEY"},
            "incomplete":{"backend":"cloud"},
            "stored":{"backend":"cloud","api_key_ref":"keyring:DO_NOT_RESOLVE"},
            "inline":{"backend":"cloud","api_key_ref":"inline:NEVER_PRINT_THIS"}
        }
    });
    std::fs::write(&path, config.to_string()).unwrap();

    let output = command(dir.path(), &["context", "list", "--format", "json"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("NEVER_PRINT_THIS"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_RESOLVE"));
    let context = success_json(output);
    assert_eq!(context["profiles"].as_array().unwrap().len(), 5);
    assert!(
        context["selection_error"]
            .as_str()
            .unwrap()
            .contains("not found")
    );

    let context = success_json(
        command(dir.path(), &["ctx", "use", "work", "--format", "json"])
            .output()
            .unwrap(),
    );
    assert_eq!(context["selected"]["profile"], "work");
    assert!(context["selection_error"].is_null());
    let mut expected = config.clone();
    expected["version"] = json!(1);
    expected["active_profile"] = json!("work");
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
        expected
    );

    let output = command(dir.path(), &["context"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("MSB_UNSET_CONTEXT_KEY"));

    let context = success_json(
        command(dir.path(), &["context", "--format", "json", "reset"])
            .output()
            .unwrap(),
    );
    assert!(context["saved_profile"].is_null());
    assert_eq!(context["selected"]["kind"], "local");
    expected.as_object_mut().unwrap().remove("active_profile");
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
        expected
    );
    assert!(!dir.path().join("runtime").exists());
}

#[test]
fn prohibited_selection_is_visible_but_cannot_be_used() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = json!({"allowed_backends":["cloud"], "profiles":{
        "local":{"backend":"local"}, "work":{"backend":"cloud"}
    }})
    .to_string();
    std::fs::write(&path, &config).unwrap();

    let context = success_json(
        command(dir.path(), &["context", "list", "--format", "json"])
            .output()
            .unwrap(),
    );
    assert_eq!(context["selected"]["kind"], "local");
    assert!(
        context["selection_error"]
            .as_str()
            .unwrap()
            .contains("disabled")
    );
    assert!(
        context["selection_error"]
            .as_str()
            .unwrap()
            .contains(path.to_str().unwrap())
    );
    assert_eq!(context["profiles"][0]["allowed"], false);
    for arguments in [vec!["context"], vec!["context", "use", "local"]] {
        let output = command(dir.path(), &arguments).output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("user config"), "{error}");
        assert!(error.contains("allowed backends: cloud"), "{error}");
        assert!(error.contains(path.to_str().unwrap()), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), config);
    }
    assert!(!dir.path().join("runtime").exists());

    for invalid in [
        r#"{"allowed_backends":[]}"#,
        r#"{"allowed_backends":["typo"]}"#,
        r#"{"version":2}"#,
    ] {
        std::fs::write(&path, invalid).unwrap();
        for arguments in [vec!["context", "list"], vec!["context", "reset"]] {
            let output = command(dir.path(), &arguments).output().unwrap();
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains(path.to_str().unwrap()), "{error}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
        }
    }
}

#[test]
fn cloud_context_uses_explicit_selection_without_contacting_the_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        r#"{"profiles":{"personal":{"backend":"local"}}}"#,
    )
    .unwrap();
    for api_key in [None, Some(""), Some(" ")] {
        let mut command = command(dir.path(), &["context", "list", "--format", "json"]);
        command.env("MSB_BACKEND", "cloud");
        if let Some(api_key) = api_key {
            command.env("MSB_API_KEY", api_key);
        }

        let context = success_json(command.output().unwrap());
        assert_eq!(context["selected"]["kind"], "cloud");
        assert!(
            context["selection_error"]
                .as_str()
                .unwrap()
                .contains("requires a non-empty MSB_API_KEY or a cloud profile")
        );
    }

    let output = command(dir.path(), &["context", "--format", "json"])
        .env("MSB_BACKEND", "cloud")
        .env("MSB_API_KEY", "NEVER_PRINT_THIS")
        .env("MSB_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    let context = success_json(output);
    assert_eq!(
        context,
        json!({"kind":"cloud","api_url":"http://127.0.0.1:1","source":"MSB_BACKEND"})
    );

    let context = success_json(
        command(
            dir.path(),
            &["context", "use", "personal", "--format", "json"],
        )
        .env("MSB_BACKEND", "cloud")
        .env("MSB_API_KEY", "NEVER_PRINT_THIS")
        .output()
        .unwrap(),
    );
    assert_eq!(context["saved_profile"], "personal");
    assert_eq!(context["selected"]["kind"], "cloud");
    assert_eq!(context["preference_overridden"], true);
    assert!(context["selection_error"].is_null());
    assert!(!dir.path().join("runtime").exists());
}
