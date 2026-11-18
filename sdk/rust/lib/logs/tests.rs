//! Local log-reader policy regressions.

use futures::TryStreamExt;

use super::*;
use crate::config::{GlobalConfig, RuntimeConfig};

async fn read_through_local_backend(strict: bool) -> Vec<MicrosandboxResult<usize>> {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let real = home.join("real-logs");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(
        real.join("exec.log"),
        "{\"t\":\"2026-04-30T20:32:59.000Z\",\"s\":\"stdout\",\"d\":\"hi\\n\",\"id\":7}\n",
    )
    .unwrap();
    let sandbox = home.join(microsandbox_utils::SANDBOXES_SUBDIR).join("sbx");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::os::unix::fs::symlink(&real, sandbox.join("logs")).unwrap();
    let local = crate::test_support::local_backend(GlobalConfig {
        home: Some(home),
        runtime: RuntimeConfig {
            strict_host_files: strict,
            ..Default::default()
        },
        ..Default::default()
    });

    let opts = LogOptions::default();
    let logger = SandboxLogger::for_local(&local, "sbx");
    let streamed = match log_stream_local(&local, "sbx", &LogStreamOptions::default()).await {
        Ok(stream) => stream.try_collect::<Vec<_>>().await.map(|e| e.len()),
        Err(error) => Err(error),
    };
    vec![
        read_logs_local(&local, "sbx", &opts).await.map(|e| e.len()),
        streamed,
        logger.read_snapshot(&opts).await.map(|s| s.entries.len()),
    ]
}

#[tokio::test]
async fn local_backend_log_readers_apply_its_strict_host_file_policy() {
    for result in read_through_local_backend(false).await {
        assert_eq!(result.unwrap(), 1);
    }

    for result in read_through_local_backend(true).await {
        let message = result.unwrap_err().to_string();
        assert!(message.contains("runtime.strict_host_files"), "{message}");
        assert!(message.contains("\"logs\""), "{message}");
    }
}
