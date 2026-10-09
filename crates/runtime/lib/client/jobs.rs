//! Versioned, bounded job history outside the guest-visible runtime directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use microsandbox_protocol::jobs::{JOB_PROTOCOL_VERSION, JobId, JobInfo, JobOutput};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum bytes in one output segment; at most two segments are retained per job.
pub const JOB_LOG_SEGMENT_BYTES: u64 = 512 * 1024;
const MAX_METADATA_BYTES: u64 = 128 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An additive job record, ignored by runtimes predating managed jobs.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredJob {
    /// Public lifecycle information.
    pub info: JobInfo,
    /// Hash of the admitted request, for duplicate-launch detection without retaining secrets.
    pub fingerprint: String,
}

/// Location of one sandbox's managed-job history.
#[derive(Clone)]
pub struct JobStore {
    root: PathBuf,
}

/// Single runtime-owned append writer with bounded rotating output.
pub struct JobLogWriter {
    directory: PathBuf,
    file: Option<File>,
    bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JobStore {
    /// Use a sandbox-owned host directory, never its guest-visible runtime mount.
    pub fn new(sandbox_directory: &Path) -> Self {
        Self {
            root: sandbox_directory.join("jobs-v1"),
        }
    }

    /// Validate the format instead of silently reinterpreting future records.
    pub fn read(&self, id: &JobId) -> io::Result<StoredJob> {
        let path = self.root.join(id.as_str()).join("info.json");
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_METADATA_BYTES {
            return Err(invalid("job metadata exceeds its size limit"));
        }
        let record: StoredJob = serde_json::from_reader(file).map_err(io::Error::other)?;
        if record.info.version != JOB_PROTOCOL_VERSION || &record.info.id != id {
            return Err(invalid("unsupported or mismatched job metadata"));
        }
        Ok(record)
    }

    /// Read retained records without creating directories or starting a VM.
    pub fn list(&self) -> io::Result<Vec<StoredJob>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = JobId::parse(name) else { continue };
            // An admission can publish its directory before the atomic metadata rename.
            match self.read(&id) {
                Ok(record) => records.push(record),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        records.sort_by(|a, b| a.info.id.cmp(&b.info.id));
        Ok(records)
    }

    /// Publish metadata atomically. Only the live runtime writes these records.
    pub fn write(&self, record: &StoredJob) -> io::Result<()> {
        let directory = self.root.join(record.info.id.as_str());
        private_directory(&self.root)?;
        private_directory(&directory)?;
        let data = serde_json::to_vec(record).map_err(io::Error::other)?;
        if data.len() as u64 > MAX_METADATA_BYTES {
            return Err(invalid("job metadata exceeds its size limit"));
        }
        let temporary = directory.join("info.next");
        let mut file = private_file(&temporary, false)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temporary, directory.join("info.json"))?;
        #[cfg(unix)]
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    /// Remove one terminal record during bounded retention pruning.
    pub fn remove(&self, id: &JobId) -> io::Result<()> {
        fs::remove_dir_all(self.root.join(id.as_str()))
    }

    /// Open the output writer after admission metadata has been published.
    pub fn writer(&self, id: &JobId) -> io::Result<JobLogWriter> {
        let directory = self.root.join(id.as_str());
        let file = private_file(&directory.join("output.jsonl"), true)?;
        let bytes = file.metadata()?.len();
        Ok(JobLogWriter {
            directory,
            file: Some(file),
            bytes,
        })
    }

    /// Read at most two bounded segments, tolerating only an incomplete final append.
    pub fn output(&self, id: &JobId) -> io::Result<Vec<JobOutput>> {
        let mut records = Vec::new();
        // Open the current inode first: rotation can then only replace the older segment.
        for name in ["output.jsonl", "output.previous.jsonl"] {
            let file = match File::open(self.root.join(id.as_str()).join(name)) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if file.metadata()?.len() > JOB_LOG_SEGMENT_BYTES + 128 * 1024 {
                return Err(invalid("job output exceeds its segment size limit"));
            }
            let mut reader = BufReader::new(file.take(JOB_LOG_SEGMENT_BYTES + 128 * 1024));
            loop {
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line)? == 0 {
                    break;
                }
                if line.last() != Some(&b'\n') {
                    break;
                }
                records.push(serde_json::from_slice::<JobOutput>(&line).map_err(io::Error::other)?);
            }
        }
        records.sort_by_key(|record| record.sequence);
        records.dedup_by_key(|record| record.sequence);
        if records
            .windows(2)
            .any(|pair| pair[0].sequence.saturating_add(1) != pair[1].sequence)
        {
            return Err(invalid(
                "output gap while reading rotating job history; retry the read",
            ));
        }
        Ok(records)
    }
}

impl JobLogWriter {
    /// Append one byte-preserving record, pruning the older segment on rollover.
    /// Any failure permanently closes this writer, preserving a readable retained prefix.
    pub fn append(&mut self, record: &JobOutput) -> io::Result<()> {
        self.append_with(record, |file, data| file.write_all(data))
    }

    fn append_with(
        &mut self,
        record: &JobOutput,
        write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.file.is_none() {
            return Err(invalid("job output capture has stopped"));
        }
        let result = self.append_inner(record, write);
        if result.is_err() {
            // A failed write_all may have left a partial final line. Readers already tolerate
            // that tail, but another append would corrupt it or introduce a sequence gap.
            self.file.take();
        }
        result
    }

    fn append_inner(
        &mut self,
        record: &JobOutput,
        write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut data = serde_json::to_vec(record).map_err(io::Error::other)?;
        data.push(b'\n');
        if self.bytes + data.len() as u64 > JOB_LOG_SEGMENT_BYTES {
            self.file.take();
            let previous = self.directory.join("output.previous.jsonl");
            match fs::remove_file(&previous) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            fs::rename(self.directory.join("output.jsonl"), previous)?;
            self.file = Some(private_file(&self.directory.join("output.jsonl"), false)?);
            self.bytes = 0;
        }
        write(
            self.file
                .as_mut()
                .ok_or_else(|| invalid("job output writer is closed"))?,
            &data,
        )?;
        self.bytes += data.len() as u64;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn private_file(path: &Path, append: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_appends_preserve_readable_history_and_never_resume() {
        for partial in [false, true] {
            for rotate in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let store = JobStore::new(directory.path());
                let id = JobId::parse(format!("job_{:032x}", 1)).unwrap();
                private_directory(&store.root.join(id.as_str())).unwrap();
                let mut writer = store.writer(&id).unwrap();
                let data = if rotate {
                    "YQ==".repeat(100 * 1024)
                } else {
                    "YQ==".into()
                };
                let first = JobOutput::new(1, 1, "stdout".into(), data.clone());
                writer.append(&first).unwrap();
                let second = JobOutput::new(2, 1, "stdout".into(), data);
                let error = writer
                    .append_with(&second, |file, bytes| {
                        if partial {
                            file.write_all(&bytes[..bytes.len() / 2])?;
                        }
                        Err(io::Error::other("injected storage failure"))
                    })
                    .unwrap_err();
                assert!(error.to_string().contains("injected storage failure"));
                // Recovery must not append to a partial JSON line or skip sequence two.
                assert!(
                    writer
                        .append(&JobOutput::new(3, 1, "stderr".into(), "Yg==".into()))
                        .is_err()
                );
                let records = store.output(&id).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].sequence, 1);
                assert_eq!(records[0].data_base64, first.data_base64);
                assert!(writer.file.is_none());
            }
        }
    }

    #[test]
    fn rotation_failure_does_not_resume_after_path_repair() {
        let directory = tempfile::tempdir().unwrap();
        let store = JobStore::new(directory.path());
        let id = JobId::parse(format!("job_{:032x}", 1)).unwrap();
        let path = store.root.join(id.as_str());
        private_directory(&path).unwrap();
        let mut writer = store.writer(&id).unwrap();
        let record =
            |sequence| JobOutput::new(sequence, 1, "stdout".into(), "YQ==".repeat(100 * 1024));
        writer.append(&record(1)).unwrap();
        // An occupied rotation destination causes a real filesystem error on every platform.
        let blocker = path.join("output.previous.jsonl");
        fs::create_dir(&blocker).unwrap();
        assert!(writer.append(&record(2)).is_err());
        fs::remove_dir(blocker).unwrap();
        assert!(writer.append(&record(3)).is_err());
        let records = store.output(&id).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 1);
    }

    #[test]
    fn output_rotation_is_bounded_binary_safe_and_keeps_exit_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let store = JobStore::new(directory.path());
        let id = JobId::parse(format!("job_{:032x}", 1)).unwrap();
        let command =
            serde_json::from_value(serde_json::json!({ "cmd": "printf", "env": ["SECRET=value"] }))
                .unwrap();
        let record = StoredJob {
            info: JobInfo::starting(id.clone(), "boot".into(), &command, false, 1),
            fingerprint: "digest".into(),
        };
        store.write(&record).unwrap();
        let persisted = fs::read_to_string(store.root.join(id.as_str()).join("info.json")).unwrap();
        assert!(!persisted.contains("SECRET"));
        let mut writer = store.writer(&id).unwrap();
        for sequence in 1..=200 {
            writer
                .append(&JobOutput::new(
                    sequence,
                    1,
                    "stdout".into(),
                    "/wAA".repeat(4 * 1024),
                ))
                .unwrap();
        }
        drop(writer);
        let output = store.output(&id).unwrap();
        assert_eq!(output.last().unwrap().sequence, 200);
        assert!(output.first().unwrap().sequence > 1);
        assert!(
            output
                .windows(2)
                .all(|items| items[0].sequence + 1 == items[1].sequence)
        );
        assert_eq!(store.read(&id).unwrap().info.id, id);
        for file in ["output.previous.jsonl", "output.jsonl"] {
            assert!(
                fs::metadata(store.root.join(id.as_str()).join(file))
                    .unwrap()
                    .len()
                    <= JOB_LOG_SEGMENT_BYTES
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&store.root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
}
