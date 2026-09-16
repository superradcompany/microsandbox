use std::sync::Arc;

use tokio::sync::Mutex;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A consumable wrapper whose admitted operations own their reference independently.
///
/// The slot lock orders admission against consumption, not guest work against lifecycle work.
/// Holding it across guest I/O would let a paused guest prevent its own resume.
pub(crate) struct SharedHandle<T> {
    inner: Mutex<Option<Arc<T>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> SharedHandle<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(Some(Arc::new(value))),
        }
    }

    /// Admit an operation without cloning the underlying sandbox configuration.
    pub(crate) async fn get(&self) -> Option<Arc<T>> {
        self.inner.lock().await.clone()
    }

    /// Reject future admissions; already admitted operations retain their references.
    pub(crate) async fn take(&self) -> Option<Arc<T>> {
        self.inner.lock().await.take()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn pending_operation_does_not_block_admission_or_consumption() {
        let handle = Arc::new(SharedHandle::new(String::from("sandbox")));
        let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let task_handle = handle.clone();
        let operation = tokio::spawn(async move {
            let reference = task_handle.get().await.unwrap();
            admitted_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            assert_eq!(reference.as_str(), "sandbox");
        });
        admitted_rx.await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            let second = handle.get().await.unwrap();
            let consumed = handle.take().await.unwrap();
            assert!(Arc::ptr_eq(&second, &consumed));
            assert!(handle.get().await.is_none());
            assert!(handle.take().await.is_none());
        })
        .await
        .expect("a pending operation must not hold the admission lock");
        finish_tx.send(()).unwrap();
        operation.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_consumers_have_exactly_one_winner() {
        let handle = SharedHandle::new(());
        let (first, second) = tokio::join!(handle.take(), handle.take());
        assert_ne!(first.is_some(), second.is_some());
        assert!(handle.get().await.is_none());
    }

    #[tokio::test]
    async fn cancellation_releases_last_admitted_reference() {
        let handle = Arc::new(SharedHandle::new(()));
        let reference = handle.get().await.unwrap();
        let weak = Arc::downgrade(&reference);
        let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
        let operation = tokio::spawn(async move {
            let _reference = reference;
            admitted_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        admitted_rx.await.unwrap();
        drop(handle.take().await);
        assert!(weak.upgrade().is_some());
        operation.abort();
        assert!(operation.await.unwrap_err().is_cancelled());
        assert!(weak.upgrade().is_none());
    }
}
