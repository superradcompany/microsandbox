//! Bounded Windows control-endpoint connection, before any request is sent.

use std::io;
use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;
const RETRY_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(super) async fn connect(
    path: &std::path::Path,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    retry_open(CONNECT_TIMEOUT, || ClientOptions::new().open(path)).await
}

async fn retry_open<T>(
    timeout: Duration,
    mut open: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    let result = tokio::time::timeout_at(deadline, async {
        loop {
            match open() {
                Ok(client) => return Ok(client),
                // The first listener instance is created asynchronously, and subsequent
                // instances are recreated between requests. Missing and busy are both
                // transient here; permission errors and other failures are not.
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY)
                    ) =>
                {
                    last_error = Some(error)
                }
                Err(error) => return Err(error),
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    })
    .await;

    match result {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "control pipe connection timed out after {timeout:?}; last open error: {}",
                last_error.map_or_else(|| "none".into(), |error| error.to_string())
            ),
        )),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_control_pipe_opens_once() {
        let mut attempts = 0;
        let value = retry_open(Duration::from_secs(1), || {
            attempts += 1;
            Ok(42)
        })
        .await
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn missing_and_busy_control_pipe_retry_before_success() {
        let mut errors = [ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_FILE_NOT_FOUND].into_iter();
        let mut attempts = 0;
        retry_open(Duration::from_secs(1), || {
            attempts += 1;
            errors
                .next()
                .map_or(Ok(()), |code| Err(io::Error::from_raw_os_error(code)))
        })
        .await
        .unwrap();
        assert_eq!(attempts, 4);
    }

    #[tokio::test]
    async fn permanent_control_pipe_errors_are_not_retried() {
        for code in [5, 3, 109] {
            let mut attempts = 0;
            let error = retry_open::<()>(Duration::from_secs(1), || {
                attempts += 1;
                Err(io::Error::from_raw_os_error(code))
            })
            .await
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(attempts, 1);
        }
    }

    #[tokio::test]
    async fn unavailable_control_pipe_has_one_total_budget() {
        for code in [ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY] {
            let mut attempts = 0;
            let error = retry_open::<()>(Duration::from_millis(35), || {
                attempts += 1;
                Err(io::Error::from_raw_os_error(code))
            })
            .await
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(error.to_string().contains("last open error"));
            assert!(attempts > 0);
        }
    }

    #[tokio::test]
    async fn enclosing_startup_deadline_cancels_control_pipe_retries() {
        let attempts = std::cell::Cell::new(0);
        let result = tokio::time::timeout(
            Duration::from_millis(25),
            retry_open::<()>(Duration::from_secs(1), || {
                attempts.set(attempts.get() + 1);
                Err(io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND))
            }),
        )
        .await;
        assert!(result.is_err());
        let stopped_at = attempts.get();
        assert!(stopped_at > 0);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(attempts.get(), stopped_at);
    }

    #[cfg(windows)]
    fn pipe_name() -> String {
        static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        format!(
            r"\\.\pipe\msb-control-connect-test-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_control_pipe_delayed_creation_preserves_response() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let name = pipe_name();
        assert_eq!(
            ClientOptions::new().open(&name).unwrap_err().raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND)
        );
        let server_name = name.clone();
        let listener = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&server_name)
                .unwrap();
            server.connect().await.unwrap();
            let mut reader = BufReader::new(server);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();
            assert_eq!(request, "{\"op\":\"cpu_state\"}\n");
            reader
                .get_mut()
                .write_all(b"{\"ok\":true}\n")
                .await
                .unwrap();
            reader.get_mut().flush().await.unwrap();
        });
        let mut client = connect(std::path::Path::new(&name)).await.unwrap();
        client.write_all(b"{\"op\":\"cpu_state\"}\n").await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            BufReader::new(client).read_line(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        listener.await.unwrap();
        assert_eq!(response, "{\"ok\":true}\n");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_control_pipe_busy_then_recreated_connects() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let name = pipe_name();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let occupied = ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();
        assert_eq!(
            ClientOptions::new().open(&name).unwrap_err().raw_os_error(),
            Some(ERROR_PIPE_BUSY)
        );
        let server_name = name.clone();
        let listener = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(occupied);
            drop(server);
            tokio::time::sleep(Duration::from_millis(30)).await;
            let server = ServerOptions::new().create(&server_name).unwrap();
            server.connect().await.unwrap();
        });
        let _client = connect(std::path::Path::new(&name)).await.unwrap();
        listener.await.unwrap();
    }
}
