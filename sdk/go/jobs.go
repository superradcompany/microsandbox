package microsandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync/atomic"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// JobError identifies managed-job failures across runtimes and SDKs.
// JobID is retained when a launch was admitted but its result is uncertain.
type JobError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	JobID   string `json:"job_id"`
}

func (e *JobError) Error() string { return e.Code + ": " + e.Message }

// JobInfo is sandbox-scoped metadata. Timestamps are Unix milliseconds.
type JobInfo struct {
	ID            string       `json:"id"`
	RuntimeBootID string       `json:"runtime_boot_id"`
	Command       []string     `json:"command"`
	State         string       `json:"state"`
	TTY           bool         `json:"tty"`
	StdinClosed   bool         `json:"stdin_closed"`
	PID           *uint32      `json:"pid"`
	CreatedAt     int64        `json:"created_at"`
	StartedAt     *int64       `json:"started_at"`
	FinishedAt    *int64       `json:"finished_at"`
	ExitCode      *int         `json:"exit_code"`
	TimedOut      bool         `json:"timed_out"`
	Failure       *ExecFailure `json:"failure"`
	Error         *string      `json:"error"`
}

// JobPage is a bounded listing. Pass NextCursor to WithJobCursor.
type JobPage struct {
	Items      []JobInfo `json:"items"`
	NextCursor *string   `json:"next_cursor"`
}

// JobExit is a confirmed result, not an inferred transport failure.
type JobExit struct {
	Code     int  `json:"code"`
	Success  bool `json:"success"`
	TimedOut bool `json:"timed_out"`
}

// JobLogEntry preserves original output bytes and a job-specific replay cursor.
type JobLogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"`
	Data      []byte `json:"data_base64"`
	Cursor    string `json:"cursor"`
}

// JobLogOptions selects retained output. Follow continues after that snapshot.
type JobLogOptions struct {
	Tail       *uint    `json:"tail,omitempty"`
	Since      *int64   `json:"since,omitempty"`
	Until      *int64   `json:"until,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	FromCursor string   `json:"from_cursor,omitempty"`
	Follow     bool     `json:"follow"`
}

// JobEvent contains one attachment observation. Only the field matching Type is populated.
type JobEvent struct {
	Type      string
	Output    *JobLogEntry
	GapCursor string
	Completed *JobInfo
}

// JobExecOption includes existing ExecOption values and detached-specific options.
type JobExecOption interface{ applyJob(*jobExecConfig) }
type jobExecConfig struct {
	ExecConfig
	input  *[]byte
	limits []JobRlimit
}

func (o ExecOption) applyJob(c *jobExecConfig) { o(&c.ExecConfig) }

type jobExecOption func(*jobExecConfig)

func (o jobExecOption) applyJob(c *jobExecConfig) { o(c) }

// JobRlimit is a Linux resource limit, for example resource "nofile".
type JobRlimit struct {
	Resource string `json:"resource"`
	Soft     uint64 `json:"soft"`
	Hard     uint64 `json:"hard"`
}

// WithJobInput provides at most 64 KiB of finite input, then EOF. Larger input uses attachment writes.
func WithJobInput(data []byte) JobExecOption {
	bytes := append([]byte{}, data...)
	return jobExecOption(func(c *jobExecConfig) { c.input = &bytes; c.StdinPipe = true })
}

// WithJobRlimits sets per-command resource limits.
func WithJobRlimits(limits ...JobRlimit) JobExecOption {
	copy := append([]JobRlimit(nil), limits...)
	return jobExecOption(func(c *jobExecConfig) { c.limits = copy })
}

// WithExecStdinNull closes detached pipe input after startup.
func WithExecStdinNull() ExecOption { return func(c *ExecConfig) { c.StdinPipe = false } }

type jobListConfig struct {
	all    bool
	limit  uint
	cursor string
}

// JobListOption configures one listing page.
type JobListOption func(*jobListConfig)

func WithAllJobs() JobListOption                { return func(c *jobListConfig) { c.all = true } }
func WithJobLimit(limit uint) JobListOption     { return func(c *jobListConfig) { c.limit = limit } }
func WithJobCursor(cursor string) JobListOption { return func(c *jobListConfig) { c.cursor = cursor } }

type jobAttachConfig struct {
	readOnly bool
	bytes    *uint
	cursor   string
}

// JobAttachOption configures temporary I/O ownership.
type JobAttachOption func(*jobAttachConfig)

func WithJobReadOnly() JobAttachOption { return func(c *jobAttachConfig) { c.readOnly = true } }
func WithJobReplayRecent(bytes uint) JobAttachOption {
	return func(c *jobAttachConfig) { c.bytes = &bytes; c.cursor = "" }
}
func WithJobReplayAfter(cursor string) JobAttachOption {
	return func(c *jobAttachConfig) { c.cursor = cursor; c.bytes = nil }
}

// Job is a native reference to a runtime-owned command. Close never terminates it.
type Job struct {
	id     string
	handle atomic.Uint64
}

func (j *Job) ID() string { return j.id }

// JobAttachment supports one concurrent receiver plus writes, resize and detach.
type JobAttachment struct{ handle atomic.Uint64 }

// JobLogStream is a bounded pull stream. Close cancels pending Next calls.
type JobLogStream struct{ handle atomic.Uint64 }

func jobRequest(ctx context.Context, sandbox uint64, request map[string]any, result any) error {
	raw, err := ffi.Jobs(ctx, sandbox, request)
	if err != nil {
		var native *ffi.Error
		if errors.As(err, &native) {
			if native.Kind == "job" {
				var e JobError
				if json.Unmarshal([]byte(native.Message), &e) == nil {
					return &e
				}
			}
			if native.Kind == "unsupported_feature" {
				return &JobError{Code: native.Kind, Message: native.Message}
			}
		}
		return wrapFFI(err)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(raw, result)
}
func newJob(ctx context.Context, sandbox uint64, request map[string]any) (*Job, error) {
	var raw struct {
		ID     string `json:"id"`
		Handle uint64 `json:"handle"`
	}
	if err := jobRequest(ctx, sandbox, request, &raw); err != nil {
		return nil, err
	}
	j := &Job{id: raw.ID}
	j.handle.Store(raw.Handle)
	runtime.SetFinalizer(j, func(j *Job) { _ = j.Close() })
	return j, nil
}

// ExecDetached confirms guest startup, then returns a durable job ID. The sandbox must be running.
// SDK input defaults to retained pipes; timeout remains enforced after this call returns.
func (s *Sandbox) ExecDetached(ctx context.Context, cmd string, args []string, opts ...JobExecOption) (*Job, error) {
	cfg := jobExecConfig{ExecConfig: ExecConfig{StdinPipe: true}}
	for _, opt := range opts {
		opt.applyJob(&cfg)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("job timeout must be positive")
	}
	options := map[string]any{"cmd": cmd, "args": args, "tty": cfg.TTY, "no_stdin": !cfg.StdinPipe, "rlimits": cfg.limits}
	if args == nil {
		options["args"] = []string{}
	}
	if cfg.limits == nil {
		delete(options, "rlimits")
	}
	if cfg.Cwd != "" {
		options["cwd"] = cfg.Cwd
	}
	if cfg.User != "" {
		options["user"] = cfg.User
	}
	if cfg.Env != nil {
		options["env"] = cfg.Env
	}
	if cfg.Timeout > 0 {
		options["timeout_ms"] = uint64((cfg.Timeout-1)/1_000_000 + 1)
	}
	if cfg.input != nil {
		options["input_base64"] = base64.StdEncoding.EncodeToString(*cfg.input)
	}
	return newJob(ctx, s.inner.Handle(), map[string]any{"op": "start", "options": options})
}
func (s *Sandbox) GetJob(ctx context.Context, id string) (*Job, error) {
	return newJob(ctx, s.inner.Handle(), map[string]any{"op": "get", "id": id})
}
func (h *SandboxHandle) GetJob(ctx context.Context, id string) (*Job, error) {
	return newJob(ctx, 0, map[string]any{"op": "get", "name": h.name, "sandbox_id": h.id, "id": id})
}
func listJobs(ctx context.Context, sandbox uint64, request map[string]any, opts []JobListOption) (*JobPage, error) {
	cfg := jobListConfig{limit: 50}
	for _, opt := range opts {
		opt(&cfg)
	}
	request["op"] = "list"
	request["all"] = cfg.all
	request["limit"] = cfg.limit
	if cfg.cursor != "" {
		request["cursor"] = cfg.cursor
	}
	var page JobPage
	err := jobRequest(ctx, sandbox, request, &page)
	return &page, err
}
func (s *Sandbox) ListJobs(ctx context.Context, opts ...JobListOption) (*JobPage, error) {
	return listJobs(ctx, s.inner.Handle(), map[string]any{}, opts)
}
func (h *SandboxHandle) ListJobs(ctx context.Context, opts ...JobListOption) (*JobPage, error) {
	return listJobs(ctx, 0, map[string]any{"name": h.name, "sandbox_id": h.id}, opts)
}

func (j *Job) request(ctx context.Context, op string, args map[string]any, result any) error {
	if args == nil {
		args = map[string]any{}
	}
	args["op"] = op
	args["handle"] = j.handle.Load()
	err := jobRequest(ctx, 0, args, result)
	runtime.KeepAlive(j)
	return err
}
func (j *Job) Inspect(ctx context.Context) (*JobInfo, error) {
	var info JobInfo
	err := j.request(ctx, "inspect", nil, &info)
	return &info, err
}

// Wait cancellation cancels only the wait. It never kills the process.
func (j *Job) Wait(ctx context.Context) (*JobExit, error) {
	var exit JobExit
	err := j.request(ctx, "wait", nil, &exit)
	return &exit, err
}
func (j *Job) Signal(ctx context.Context, signal int) error {
	return j.request(ctx, "signal", map[string]any{"signal": signal}, nil)
}
func (j *Job) Kill(ctx context.Context) error { return j.request(ctx, "kill", nil, nil) }
func (j *Job) EOF(ctx context.Context) error  { return j.request(ctx, "eof", nil, nil) }
func (j *Job) Logs(ctx context.Context, options JobLogOptions) ([]JobLogEntry, error) {
	var logs []JobLogEntry
	err := j.request(ctx, "logs", map[string]any{"options": options}, &logs)
	return logs, err
}
func (j *Job) LogStream(ctx context.Context, options JobLogOptions) (*JobLogStream, error) {
	var raw struct {
		Handle uint64 `json:"handle"`
	}
	if err := j.request(ctx, "log_stream", map[string]any{"options": options}, &raw); err != nil {
		return nil, err
	}
	stream := &JobLogStream{}
	stream.handle.Store(raw.Handle)
	runtime.SetFinalizer(stream, func(s *JobLogStream) { _ = s.Close() })
	return stream, nil
}
func (j *Job) FollowLogs(ctx context.Context, options JobLogOptions) (*JobLogStream, error) {
	options.Follow = true
	return j.LogStream(ctx, options)
}
func (j *Job) Attach(ctx context.Context, opts ...JobAttachOption) (*JobAttachment, error) {
	cfg := jobAttachConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	args := map[string]any{"read_only": cfg.readOnly}
	if cfg.bytes != nil {
		args["replay_bytes"] = *cfg.bytes
	}
	if cfg.cursor != "" {
		args["cursor"] = cfg.cursor
	}
	var raw struct {
		Handle uint64 `json:"handle"`
	}
	if err := j.request(ctx, "attach", args, &raw); err != nil {
		return nil, err
	}
	a := &JobAttachment{}
	a.handle.Store(raw.Handle)
	runtime.SetFinalizer(a, func(a *JobAttachment) { _ = a.Close() })
	return a, nil
}
func closeJobObject(handle *atomic.Uint64) error {
	id := handle.Swap(0)
	if id == 0 {
		return nil
	}
	return jobRequest(context.Background(), 0, map[string]any{"op": "close", "handle": id}, nil)
}
func (j *Job) Close() error           { runtime.SetFinalizer(j, nil); return closeJobObject(&j.handle) }
func (a *JobAttachment) Close() error { runtime.SetFinalizer(a, nil); return closeJobObject(&a.handle) }
func (s *JobLogStream) Close() error  { runtime.SetFinalizer(s, nil); return closeJobObject(&s.handle) }
func (a *JobAttachment) request(ctx context.Context, op string, args map[string]any, result any) error {
	if args == nil {
		args = map[string]any{}
	}
	args["op"] = op
	args["handle"] = a.handle.Load()
	err := jobRequest(ctx, 0, args, result)
	runtime.KeepAlive(a)
	return err
}
func (a *JobAttachment) Recv(ctx context.Context) (*JobEvent, error) {
	var raw *struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := a.request(ctx, "recv", nil, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, io.EOF
	}
	event := &JobEvent{Type: raw.Type}
	switch raw.Type {
	case "output":
		event.Output = &JobLogEntry{}
		if err := json.Unmarshal(raw.Value, event.Output); err != nil {
			return nil, err
		}
	case "completed":
		event.Completed = &JobInfo{}
		if err := json.Unmarshal(raw.Value, event.Completed); err != nil {
			return nil, err
		}
	case "gap":
		var value struct {
			Cursor string `json:"cursor"`
		}
		if err := json.Unmarshal(raw.Value, &value); err != nil {
			return nil, err
		}
		event.GapCursor = value.Cursor
	default:
		return nil, fmt.Errorf("unknown job event %q", raw.Type)
	}
	return event, nil
}
func (a *JobAttachment) WriteStdin(ctx context.Context, data []byte) error {
	return a.request(ctx, "write", map[string]any{"data_base64": base64.StdEncoding.EncodeToString(data)}, nil)
}
func (a *JobAttachment) Resize(ctx context.Context, rows, cols uint16) error {
	return a.request(ctx, "resize", map[string]any{"rows": rows, "cols": cols}, nil)
}
func (a *JobAttachment) Detach(ctx context.Context) error { return a.request(ctx, "detach", nil, nil) }
func (s *JobLogStream) Next(ctx context.Context) (*JobLogEntry, error) {
	var entry *JobLogEntry
	err := jobRequest(ctx, 0, map[string]any{"op": "next", "handle": s.handle.Load()}, &entry)
	runtime.KeepAlive(s)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, io.EOF
	}
	return entry, nil
}
