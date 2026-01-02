#[cfg(feature = "cli")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "cli")]
use microsandbox_utils::MULTI_PROGRESS;
#[cfg(feature = "cli")]
use pin_project_lite::pin_project;
#[cfg(feature = "cli")]
use std::task::Poll;
#[cfg(feature = "cli")]
use tokio::io::{AsyncRead, ReadBuf};

#[cfg(feature = "cli")]
pub(super) fn build_progress_bar(total_bytes: u64, prefix: &str) -> ProgressBar {
    let pb = MULTI_PROGRESS.add(ProgressBar::new(total_bytes));
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold.dim} {bar:40.green/green.dim} {bytes:.bold}/{total_bytes:.dim}",
        )
        .unwrap()
        .progress_chars("=+-"),
    );
    pb.set_prefix(prefix.to_string());
    pb
}

#[cfg(feature = "cli")]
pin_project! {
    pub(super) struct ProgressReader<R> {
        #[pin]
        pub(super) inner: R,
        pub(super) bar: ProgressBar,
    }
}

#[cfg(feature = "cli")]
impl<R: AsyncRead> AsyncRead for ProgressReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let p = self.project();
        match p.inner.poll_read(cx, buf)? {
            Poll::Ready(()) => {
                let n = buf.filled().len();
                if n > 0 {
                    p.bar.inc(n as u64);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
