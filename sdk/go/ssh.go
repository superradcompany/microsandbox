package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// SSH is the SSH operations for a sandbox.
type SandboxSSHOps struct {
	sandbox *Sandbox
}

// SSH returns the SSH operations for this sandbox.
func (s *Sandbox) SSH() *SandboxSSHOps {
	return &SandboxSSHOps{sandbox: s}
}

// SSHClientOption configures SandboxSSHOps.OpenClient.
type SSHClientOption func(*sshClientConfig)

type sshClientConfig struct {
	user string
	term string
	sftp *bool
}

// WithSSHUser sets the SSH login user.
func WithSSHUser(user string) SSHClientOption {
	return func(o *sshClientConfig) { o.user = user }
}

// WithSSHTerm sets the terminal name for interactive SSH sessions.
func WithSSHTerm(term string) SSHClientOption {
	return func(o *sshClientConfig) { o.term = term }
}

// WithSSHClientSFTP enables or disables SFTP for the internal client server.
func WithSSHClientSFTP(enabled bool) SSHClientOption {
	return func(o *sshClientConfig) { o.sftp = &enabled }
}

// SSHClient is a native in-process SSH client session.
type SSHClient struct {
	inner *ffi.SSHClient
}

// OpenClient opens a native in-process SSH client to this sandbox.
func (ssh *SandboxSSHOps) OpenClient(ctx context.Context, opts ...SSHClientOption) (*SSHClient, error) {
	cfg := sshClientConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	inner, err := ssh.sandbox.inner.SSHConnect(ctx, ffi.SSHClientOptions{
		User: cfg.user,
		Term: cfg.term,
		SFTP: cfg.sftp,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &SSHClient{inner: inner}, nil
}

// SSHExecOption configures SSHClient.Exec.
type SSHExecOption func(*sshExecConfig)

type sshExecConfig struct {
	tty *bool
}

// WithSSHTTY requests a PTY for an SSH exec request.
func WithSSHTTY(enabled bool) SSHExecOption {
	return func(o *sshExecConfig) { o.tty = &enabled }
}

// SSHOutput is the output from an SSH exec request.
type SSHOutput struct {
	Status int
	Stdout []byte
	Stderr []byte
}

// Success reports whether the command exited with status 0.
func (o SSHOutput) Success() bool {
	return o.Status == 0
}

// Exec runs an SSH exec request and collects stdout, stderr, and exit status.
func (c *SSHClient) Exec(ctx context.Context, command string, opts ...SSHExecOption) (*SSHOutput, error) {
	cfg := sshExecConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	out, err := c.inner.Exec(ctx, command, ffi.SSHExecOptions{TTY: cfg.tty})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &SSHOutput{
		Status: out.Status,
		Stdout: out.Stdout,
		Stderr: out.Stderr,
	}, nil
}

// SSHAttachOption configures SSHClient.Attach.
type SSHAttachOption func(*sshAttachConfig)

type sshAttachConfig struct {
	term       string
	detachKeys string
}

// WithSSHAttachTerm sets the terminal name for an interactive SSH shell.
func WithSSHAttachTerm(term string) SSHAttachOption {
	return func(o *sshAttachConfig) { o.term = term }
}

// WithSSHDetachKeys sets the detach key sequence.
func WithSSHDetachKeys(keys string) SSHAttachOption {
	return func(o *sshAttachConfig) { o.detachKeys = keys }
}

// Attach bridges the local terminal to an interactive SSH shell.
func (c *SSHClient) Attach(ctx context.Context, opts ...SSHAttachOption) (int, error) {
	cfg := sshAttachConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	status, err := c.inner.Attach(ctx, ffi.SSHAttachOptions{
		Term:       cfg.term,
		DetachKeys: cfg.detachKeys,
	})
	return status, wrapFFI(err)
}

// SFTP opens an SFTP session over this SSH connection.
func (c *SSHClient) SFTP(ctx context.Context) (*SFTPClient, error) {
	inner, err := c.inner.SFTP(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &SFTPClient{inner: inner}, nil
}

// Close closes this SSH client session. The handle is consumed.
func (c *SSHClient) Close(ctx context.Context) error {
	return wrapFFI(c.inner.Close(ctx))
}

// SFTPClient is a high-level SFTP client session.
type SFTPClient struct {
	inner *ffi.SFTPClient
}

// Read reads a file into memory.
func (sftp *SFTPClient) Read(ctx context.Context, path string) ([]byte, error) {
	data, err := sftp.inner.Read(ctx, path)
	return data, wrapFFI(err)
}

// Write writes a file, creating or truncating it.
func (sftp *SFTPClient) Write(ctx context.Context, path string, data []byte) error {
	return wrapFFI(sftp.inner.Write(ctx, path, data))
}

// Mkdir creates a directory.
func (sftp *SFTPClient) Mkdir(ctx context.Context, path string) error {
	return wrapFFI(sftp.inner.Mkdir(ctx, path))
}

// RemoveFile removes a file.
func (sftp *SFTPClient) RemoveFile(ctx context.Context, path string) error {
	return wrapFFI(sftp.inner.RemoveFile(ctx, path))
}

// RemoveDir removes an empty directory.
func (sftp *SFTPClient) RemoveDir(ctx context.Context, path string) error {
	return wrapFFI(sftp.inner.RemoveDir(ctx, path))
}

// Rename renames a file or directory.
func (sftp *SFTPClient) Rename(ctx context.Context, oldPath string, newPath string) error {
	return wrapFFI(sftp.inner.Rename(ctx, oldPath, newPath))
}

// RealPath resolves a path to its canonical absolute form.
func (sftp *SFTPClient) RealPath(ctx context.Context, path string) (string, error) {
	resolved, err := sftp.inner.RealPath(ctx, path)
	return resolved, wrapFFI(err)
}

// ReadLink reads a symlink target.
func (sftp *SFTPClient) ReadLink(ctx context.Context, path string) (string, error) {
	target, err := sftp.inner.ReadLink(ctx, path)
	return target, wrapFFI(err)
}

// Symlink creates a symlink.
func (sftp *SFTPClient) Symlink(ctx context.Context, target string, linkPath string) error {
	return wrapFFI(sftp.inner.Symlink(ctx, target, linkPath))
}

// Close closes this SFTP session. The handle is consumed.
func (sftp *SFTPClient) Close(ctx context.Context) error {
	return wrapFFI(sftp.inner.Close(ctx))
}

// SSHServerOption configures SandboxSSHOps.PrepareServer.
type SSHServerOption func(*sshServerConfig)

type sshServerConfig struct {
	hostKeyPath        string
	authorizedKeysPath string
	user               string
	sftp               *bool
}

// WithSSHHostKeyPath overrides the host private key path.
func WithSSHHostKeyPath(path string) SSHServerOption {
	return func(o *sshServerConfig) { o.hostKeyPath = path }
}

// WithSSHAuthorizedKeysPath overrides the authorized-keys path.
func WithSSHAuthorizedKeysPath(path string) SSHServerOption {
	return func(o *sshServerConfig) { o.authorizedKeysPath = path }
}

// WithSSHServerUser overrides the guest user used for SSH exec requests.
func WithSSHServerUser(user string) SSHServerOption {
	return func(o *sshServerConfig) { o.user = user }
}

// WithSSHServerSFTP enables or disables SFTP for the server endpoint.
func WithSSHServerSFTP(enabled bool) SSHServerOption {
	return func(o *sshServerConfig) { o.sftp = &enabled }
}

// SSHServer is a prepared SSH server endpoint for a sandbox.
type SSHServer struct {
	inner *ffi.SSHServer
}

// PrepareServer prepares a reusable SSH server endpoint for this sandbox.
func (ssh *SandboxSSHOps) PrepareServer(ctx context.Context, opts ...SSHServerOption) (*SSHServer, error) {
	cfg := sshServerConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	inner, err := ssh.sandbox.inner.SSHServer(ctx, ffi.SSHServerOptions{
		HostKeyPath:        cfg.hostKeyPath,
		AuthorizedKeysPath: cfg.authorizedKeysPath,
		User:               cfg.user,
		SFTP:               cfg.sftp,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &SSHServer{inner: inner}, nil
}

// Close releases this prepared server endpoint. The handle is consumed.
func (srv *SSHServer) Close(ctx context.Context) error {
	return wrapFFI(srv.inner.Close(ctx))
}

// ServeConnection serves one SSH transport over this process's stdin/stdout.
func (srv *SSHServer) ServeConnection(ctx context.Context) error {
	return wrapFFI(srv.inner.ServeConnection(ctx))
}
