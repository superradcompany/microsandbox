//! Runtime-owned command jobs, retained history, and temporary I/O attachments.

mod attachment;
mod client;
mod encoding;
mod execution;
mod terminal;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use attachment::JobAttachment;
pub use client::Job;
pub use microsandbox_protocol::jobs::{JobId, JobInfo, JobPage, JobState};
pub use types::{
    JobAttachOptionsBuilder, JobError, JobEvent, JobExit, JobListBuilder, JobLogEntry,
    JobLogOptions, JobLogStream, JobReplay, JobResult,
};
