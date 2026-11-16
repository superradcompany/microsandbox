package microsandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// NativeInstallOptions describes one exact, trusted release artifact. SHA256 must
// come from trusted release metadata, not a checksum fetched from an arbitrary mirror.
// Target is os-arch (Linux additionally requires -gnu); empty selects this host.
type NativeInstallOptions struct {
	Kind     ContextKind
	Source   string
	SHA256   string
	Target   string
	CacheDir string
}

type nativeReceipt struct {
	Version string      `json:"version"`
	Kind    ContextKind `json:"kind"`
	Target  string      `json:"target"`
	SHA256  string      `json:"sha256"`
}

func nativeTarget() string {
	target := runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "linux" {
		target += "-gnu"
	}
	return target
}
func nativeFilename(target string) (string, error) {
	switch target {
	case "darwin-arm64":
		return "libmicrosandbox_go_ffi.dylib", nil
	case "linux-amd64-gnu", "linux-arm64-gnu":
		return "libmicrosandbox_go_ffi.so", nil
	case "windows-amd64", "windows-arm64":
		return "microsandbox_go_ffi.dll", nil
	default:
		return "", fmt.Errorf("unsupported native target %q (Linux requires a glibc target)", target)
	}
}
func nativeCacheDirectory(cache string, kind ContextKind, target string) (string, error) {
	if kind != ContextLocal && kind != ContextRemote {
		return "", fmt.Errorf("unknown provider kind %q", kind)
	}
	if _, err := nativeFilename(target); err != nil {
		return "", err
	}
	if cache == "" {
		var err error
		cache, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
		cache = filepath.Join(cache, "microsandbox", "ffi")
	}
	// Capture relative cache roots before returning a path used after setup.
	return filepath.Abs(filepath.Join(cache, SDKVersion(), string(kind), target))
}

// InstallNativeProvider explicitly provisions only one FFI library. It never
// downloads a runtime or firmware and never loads a cross-target library.
// HTTPS mirrors and offline files use the same mandatory trusted digest check.
func InstallNativeProvider(ctx context.Context, options NativeInstallOptions) (string, error) {
	digest, err := hex.DecodeString(options.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("provide a trusted 64-character SHA256 digest")
	}
	target := options.Target
	if target == "" {
		target = nativeTarget()
	}
	root, err := nativeCacheDirectory(options.CacheDir, options.Kind, target)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	lock, err := os.OpenFile(filepath.Join(root, ".install-lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("native setup lock: %w; another install may be active", err)
	}
	defer os.Remove(lock.Name())
	if err := lock.Close(); err != nil {
		return "", fmt.Errorf("close native setup lock: %w", err)
	}
	source, err := openNativeSource(ctx, options.Source)
	if err != nil {
		return "", err
	}
	defer source.Close()
	file, err := os.CreateTemp(root, ".native-")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	hash := sha256.New()
	// Reject unexpectedly large payloads instead of filling the host disk.
	const maximum = int64(1 << 30)
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, maximum+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if count > maximum {
		return "", fmt.Errorf("native artifact exceeds 1 GiB")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != strings.ToLower(options.SHA256) {
		return "", fmt.Errorf("native artifact SHA256 mismatch")
	}
	name, _ := nativeFilename(target)
	destination := filepath.Join(root, actual, name)
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(file.Name(), 0700); err != nil {
		return "", err
	}
	// Content-addressed files are immutable, including while loaded by another process.
	if existing, err := os.ReadFile(destination); err == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) != actual {
			return "", fmt.Errorf("cached native artifact is corrupt")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	} else if err := os.Rename(file.Name(), destination); err != nil {
		return "", err
	}
	receipt, _ := json.Marshal(nativeReceipt{SDKVersion(), options.Kind, target, actual})
	if err := writeFile(filepath.Join(root, "installed.json"), receipt, 0600); err != nil {
		return "", err
	}
	return destination, nil
}

func openNativeSource(ctx context.Context, source string) (io.ReadCloser, error) {
	if strings.HasPrefix(source, "https://") {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Scheme != "https" {
				return fmt.Errorf("native download redirect must remain HTTPS")
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many native download redirects")
			}
			return nil
		}}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("native download: HTTP %d", response.StatusCode)
		}
		return response.Body, nil
	}
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" && len(parsed.Scheme) > 1 {
		return nil, fmt.Errorf("native source must be an HTTPS URL or local file")
	}
	return os.Open(source)
}

// InstalledNativeProvider verifies the selected cached file before loading it.
// An empty cache selects the OS user cache. Import and first use never install it.
func InstalledNativeProvider(kind ContextKind, cache string) (*NativeProvider, error) {
	target := nativeTarget()
	root, err := nativeCacheDirectory(cache, kind, target)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, "installed.json"))
	if err != nil {
		return nil, fmt.Errorf("missing %s native provider: run the explicit ffi-setup command or provide a library path: %w", kind, err)
	}
	var receipt nativeReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(receipt.SHA256)
	if err != nil || len(digest) != sha256.Size || receipt.Version != SDKVersion() || receipt.Kind != kind || receipt.Target != target {
		return nil, fmt.Errorf("incompatible native install receipt; provision the matching provider")
	}
	name, _ := nativeFilename(target)
	path := filepath.Join(root, receipt.SHA256, name)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	file.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if hex.EncodeToString(hash.Sum(nil)) != receipt.SHA256 {
		return nil, fmt.Errorf("installed native provider SHA256 mismatch")
	}
	return LoadNativeProvider(path, kind)
}
